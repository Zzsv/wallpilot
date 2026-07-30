from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from fastapi.testclient import TestClient

from wallpilot.app import create_app
from wallpilot.config import Settings
from wallpilot.control import ControlPlane
from wallpilot.firewall import FirewallAdapter
from wallpilot.models import (
    BackendName,
    FirewallCapabilities,
    FirewallObject,
    FirewallRule,
    FirewallStatus,
    ServiceAction,
)
from wallpilot.runner import FakeRunner
from wallpilot.security import totp_code
from wallpilot.storage import Store
from wallpilot.system_info import collect_profile


class MemoryAdapter(FirewallAdapter):
    backend = BackendName.UFW

    def __init__(self, backend: BackendName = BackendName.UFW) -> None:
        super().__init__(FakeRunner())
        self.backend = backend
        self.items: dict[str, FirewallRule] = {}
        self.objects: dict[tuple[str, str], FirewallObject] = {}
        self.actions: list[str] = []

    def status(self) -> FirewallStatus:
        return FirewallStatus(
            backend=self.backend,
            active=True,
            enabled=True,
            service_unit=(
                "firewalld.service"
                if self.backend == BackendName.FIREWALLD
                else "ufw.service"
            ),
            default_policy="deny",
            capabilities=FirewallCapabilities(
                backend=self.backend,
                writable=True,
                service_actions=list(ServiceAction),
                features=["ports"],
            ),
        )

    def list_rules(self) -> list[FirewallRule]:
        return list(self.items.values())

    def apply_rule(self, operation: str, rule: FirewallRule, *, permanent: bool) -> None:
        self.actions.append(f"{operation}:{rule.id}:{permanent}")
        if operation in {"add", "restore"}:
            self.items[rule.id] = rule
        else:
            self.items.pop(rule.id, None)

    def service_action(self, action: ServiceAction) -> None:
        self.actions.append(f"service:{action.value}")

    def list_objects(self) -> list[dict[str, object]]:
        return [
            {
                "backend": item.backend.value,
                "object_type": item.object_type,
                "name": item.name,
                "builtin": item.builtin,
            }
            for item in self.objects.values()
        ]

    def get_object(self, object_type: str, name: str) -> FirewallObject:
        try:
            return self.objects[(object_type, name)]
        except KeyError as exc:
            raise ValueError("object not found") from exc

    def apply_object(
        self,
        operation: str,
        item: FirewallObject,
        *,
        before: FirewallObject | None = None,
    ) -> None:
        key = (item.object_type, item.name)
        self.actions.append(f"object:{operation}:{item.object_type}:{item.name}")
        if operation in {"add", "restore", "update"}:
            self.objects[key] = item
        elif operation == "delete":
            self.objects.pop(key, None)


@contextmanager
def initialized_client(
    tmp_path: Path,
    *,
    backend: BackendName = BackendName.UFW,
) -> Iterator[tuple[TestClient, str, Store, MemoryAdapter]]:
    settings = Settings(state_dir=tmp_path, apply_timeout_seconds=30)
    access = settings.ensure_access_path()
    store = Store(settings)
    bootstrap = store.ensure_bootstrap()
    store.create_admin(
        bootstrap["token"],
        "Correct-Horse-42!",
        totp_code(bootstrap["totp_secret"]),
    )
    adapter = MemoryAdapter(backend)
    profile = collect_profile({"ID": "ubuntu", "VERSION_ID": "24.04"})
    control = ControlPlane(
        settings,
        store,
        runner=FakeRunner(),
        profile=profile,
        adapter=adapter,
    )
    app = create_app(settings, store, control)
    prefix = f"/manage/{access}"
    with TestClient(app) as client:
        with store.connect() as conn:
            secret = conn.execute("SELECT totp_secret FROM admin WHERE id=1").fetchone()[0]
        response = client.post(
            f"{prefix}/api/v1/auth/login",
            json={"password": "Correct-Horse-42!", "totp": totp_code(secret)},
        )
        assert response.status_code == 200
        client.headers["X-CSRF-Token"] = response.json()["csrf"]
        yield client, prefix, store, adapter


def test_unknown_management_path_returns_404(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, _adapter):
        assert client.get("/").status_code == 404
        assert client.get("/manage/not-the-secret/").status_code == 404
        assert client.get(prefix + "/").status_code == 200


def test_host_header_is_restricted(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, _adapter):
        assert client.get(
            f"{prefix}/api/v1/auth/state", headers={"Host": "attacker.example"}
        ).status_code == 400


def test_csrf_is_required_for_mutations(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, _adapter):
        csrf = client.headers.pop("X-CSRF-Token")
        response = client.post(
            f"{prefix}/api/v1/drafts",
            json={
                "operation": "add",
                "object_type": "rule",
                "payload": {"backend": "ufw", "port": "443", "protocol": "tcp"},
            },
        )
        assert response.status_code == 403
        client.headers["X-CSRF-Token"] = csrf


def test_delete_is_confirmed_then_recoverable(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, store, adapter):
        rule = FirewallRule(backend="ufw", port="443", protocol="tcp", comment="web")
        adapter.items[rule.id] = rule
        created = client.post(
            f"{prefix}/api/v1/drafts",
            json={
                "operation": "delete",
                "object_type": "rule",
                "payload": rule.model_dump(mode="json"),
                "reason": "test delete",
            },
        )
        assert created.status_code == 200
        document = created.json()
        draft_id = document["draft"]["id"]
        confirmed = client.post(
            f"{prefix}/api/v1/drafts/{draft_id}/confirm",
            json={"code": document["confirmation_code"]},
        )
        assert confirmed.status_code == 200
        apply_id = confirmed.json()["apply_session"]["id"]
        assert rule.id not in adapter.items
        final = client.post(f"{prefix}/api/v1/apply-sessions/{apply_id}/confirm", json={})
        assert final.status_code == 200
        recycle = client.get(f"{prefix}/api/v1/recycle-bin").json()
        assert len(recycle) == 1
        assert recycle[0]["fingerprint"] == rule.id
        assert recycle[0]["integrity_ok"]


def test_non_firewall_service_cannot_be_controlled(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, adapter):
        response = client.post(
            f"{prefix}/api/v1/firewall/service-action", json={"action": "restart"}
        )
        assert response.status_code == 200
        assert "service:restart" in adapter.actions
        # The public API contains no unit name field, so an arbitrary unit cannot be supplied.
        response = client.post(
            f"{prefix}/api/v1/firewall/service-action",
            json={"action": "restart", "unit": "sshd.service"},
        )
        assert response.status_code == 422
        assert all("sshd" not in action for action in adapter.actions)


def test_unconfirmed_rule_change_can_be_rolled_back(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, adapter):
        rule = FirewallRule(backend="ufw", port="8080", protocol="tcp")
        created = client.post(
            f"{prefix}/api/v1/drafts",
            json={
                "operation": "add",
                "object_type": "rule",
                "payload": rule.model_dump(mode="json"),
            },
        ).json()
        applied = client.post(
            f"{prefix}/api/v1/drafts/{created['draft']['id']}/confirm",
            json={"code": created["confirmation_code"]},
        ).json()["apply_session"]
        assert rule.id in adapter.items
        response = client.post(
            f"{prefix}/api/v1/apply-sessions/{applied['id']}/rollback", json={}
        )
        assert response.status_code == 200
        assert rule.id not in adapter.items


def test_stopping_firewall_requires_strong_confirmation_and_is_reversible(
    tmp_path: Path,
) -> None:
    with initialized_client(tmp_path) as (client, prefix, store, adapter):
        rejected = client.post(
            f"{prefix}/api/v1/firewall/service-action",
            json={"action": "stop"},
        )
        assert rejected.status_code == 400
        with store.connect() as conn:
            secret = conn.execute("SELECT totp_secret FROM admin WHERE id=1").fetchone()[0]
        hostname = client.get(f"{prefix}/api/v1/auth/state").json()["hostname"]
        accepted = client.post(
            f"{prefix}/api/v1/firewall/service-action",
            json={
                "action": "stop",
                "totp": totp_code(secret),
                "hostname": hostname,
            },
        )
        assert accepted.status_code == 200
        apply_id = accepted.json()["apply_session"]["id"]
        client.post(f"{prefix}/api/v1/apply-sessions/{apply_id}/rollback", json={})
        assert "service:stop" in adapter.actions
        assert "service:start" in adapter.actions


def test_advanced_object_delete_is_recoverable_with_strong_confirmation(
    tmp_path: Path,
) -> None:
    with initialized_client(
        tmp_path, backend=BackendName.FIREWALLD
    ) as (client, prefix, store, adapter):
        with store.connect() as conn:
            secret = conn.execute("SELECT totp_secret FROM admin WHERE id=1").fetchone()[0]
        hostname = client.get(f"{prefix}/api/v1/auth/state").json()["hostname"]
        item = FirewallObject(
            object_type="zone",
            name="trusted-office",
            settings={
                "target": "ACCEPT",
                "services": ["ssh"],
                "sources": ["10.0.0.0/8"],
            },
        )
        adapter.objects[("service", "ssh")] = FirewallObject(
            object_type="service",
            name="ssh",
            builtin=True,
            settings={"ports": [{"port": "22", "protocol": "tcp"}]},
        )

        created = client.post(
            f"{prefix}/api/v1/drafts",
            json={
                "operation": "add",
                "object_type": "zone",
                "payload": {"object": item.model_dump(mode="json")},
                "reason": "create test zone",
            },
        ).json()
        applied = client.post(
            f"{prefix}/api/v1/drafts/{created['draft']['id']}/confirm",
            json={
                "code": created["confirmation_code"],
                "totp": totp_code(secret),
                "hostname": hostname,
            },
        )
        assert applied.status_code == 200
        create_apply_id = applied.json()["apply_session"]["id"]
        assert ("zone", "trusted-office") in adapter.objects
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{create_apply_id}/confirm", json={}
        ).status_code == 200

        deleted = client.post(
            f"{prefix}/api/v1/drafts",
            json={
                "operation": "delete",
                "object_type": "zone",
                "payload": {"object": item.model_dump(mode="json")},
                "reason": "delete test zone",
            },
        ).json()
        removed = client.post(
            f"{prefix}/api/v1/drafts/{deleted['draft']['id']}/confirm",
            json={
                "code": deleted["confirmation_code"],
                "totp": totp_code(secret),
                "hostname": hostname,
            },
        )
        assert removed.status_code == 200
        delete_apply_id = removed.json()["apply_session"]["id"]
        assert ("zone", "trusted-office") not in adapter.objects
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{delete_apply_id}/confirm", json={}
        ).status_code == 200

        recycle = client.get(f"{prefix}/api/v1/recycle-bin").json()
        assert len(recycle) == 1
        restored = client.post(
            f"{prefix}/api/v1/recycle-bin/{recycle[0]['id']}/restore", json={}
        )
        assert restored.status_code == 200
        restore_document = restored.json()
        assert restore_document["draft"]["requires_totp"]
        restore_apply = client.post(
            f"{prefix}/api/v1/drafts/{restore_document['draft']['id']}/confirm",
            json={
                "code": restore_document["confirmation_code"],
                "totp": totp_code(secret),
                "hostname": hostname,
            },
        )
        assert restore_apply.status_code == 200
        restore_apply_id = restore_apply.json()["apply_session"]["id"]
        assert ("zone", "trusted-office") in adapter.objects
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{restore_apply_id}/confirm", json={}
        ).status_code == 200
        assert client.get(f"{prefix}/api/v1/recycle-bin").json() == []


def test_builtin_firewalld_object_cannot_be_deleted(tmp_path: Path) -> None:
    with initialized_client(
        tmp_path, backend=BackendName.FIREWALLD
    ) as (client, prefix, _store, adapter):
        item = FirewallObject(
            object_type="zone",
            name="public",
            builtin=True,
            settings={"target": "DEFAULT"},
        )
        adapter.objects[("zone", "public")] = item
        response = client.post(
            f"{prefix}/api/v1/drafts",
            json={
                "operation": "delete",
                "object_type": "zone",
                "payload": {"object": item.model_dump(mode="json")},
            },
        )
        assert response.status_code == 422
        assert ("zone", "public") in adapter.objects


def test_confirmed_temporary_ufw_rule_expires_after_restart_safe_schedule(
    tmp_path: Path,
) -> None:
    with initialized_client(tmp_path) as (client, prefix, store, adapter):
        rule = FirewallRule(
            backend="ufw",
            port="9443",
            protocol="tcp",
            temporary_seconds=300,
            comment="temporary test",
        )
        draft = client.post(
            f"{prefix}/api/v1/drafts",
            json={
                "operation": "add",
                "object_type": "rule",
                "payload": {"rule": rule.model_dump(mode="json")},
            },
        ).json()
        applied = client.post(
            f"{prefix}/api/v1/drafts/{draft['draft']['id']}/confirm",
            json={"code": draft["confirmation_code"]},
        ).json()
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{applied['apply_session']['id']}/confirm",
            json={},
        ).status_code == 200
        assert rule.id in adapter.items
        with store.connect() as conn:
            row = conn.execute(
                "SELECT status FROM temporary_rules WHERE id=?", (rule.id,)
            ).fetchone()
            assert row["status"] == "active"
            conn.execute(
                "UPDATE temporary_rules SET expires_at='2000-01-01T00:00:00+00:00' "
                "WHERE id=?",
                (rule.id,),
            )
        expired = client.app.state.control.expire_temporary_rules()
        assert expired == [rule.id]
        assert rule.id not in adapter.items


def test_diagnostics_redacts_hostname_and_rule_addresses(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, adapter):
        rule = FirewallRule(
            backend="ufw",
            port="22",
            protocol="tcp",
            source="198.51.100.42/32",
        )
        adapter.items[rule.id] = rule
        document = client.get(f"{prefix}/api/v1/diagnostics").json()
        assert document["status"]["profile"]["hostname"].startswith("<redacted:")
        assert document["firewall_rules"][0]["source"].startswith("<redacted:")
        assert "198.51.100.42" not in str(document)


def test_json_batch_import_and_export_use_one_safe_apply_session(
    tmp_path: Path,
) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, adapter):
        rules = [
            FirewallRule(backend="ufw", port="8080", protocol="tcp"),
            FirewallRule(backend="ufw", port="8443", protocol="tcp"),
        ]
        imported = client.post(
            f"{prefix}/api/v1/import",
            json={
                "format": "wallpilot-config",
                "version": 1,
                "rules": [rule.model_dump(mode="json") for rule in rules],
                "objects": [],
            },
        )
        assert imported.status_code == 200
        document = imported.json()
        applied = client.post(
            f"{prefix}/api/v1/drafts/{document['draft']['id']}/confirm",
            json={"code": document["confirmation_code"]},
        )
        assert applied.status_code == 200
        apply_id = applied.json()["apply_session"]["id"]
        assert all(rule.id in adapter.items for rule in rules)
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{apply_id}/confirm", json={}
        ).status_code == 200

        exported = client.get(f"{prefix}/api/v1/export")
        assert exported.status_code == 200
        assert exported.json()["format"] == "wallpilot-config"
        assert {item["id"] for item in exported.json()["rules"]} == {
            rule.id for rule in rules
        }


def test_batch_import_rolls_back_all_runtime_rules(tmp_path: Path) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, adapter):
        rules = [
            FirewallRule(backend="ufw", port="8081", protocol="tcp"),
            FirewallRule(backend="ufw", port="8082", protocol="tcp"),
        ]
        document = client.post(
            f"{prefix}/api/v1/import",
            json={"rules": [rule.model_dump(mode="json") for rule in rules]},
        ).json()
        applied = client.post(
            f"{prefix}/api/v1/drafts/{document['draft']['id']}/confirm",
            json={"code": document["confirmation_code"]},
        ).json()
        assert all(rule.id in adapter.items for rule in rules)
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{applied['apply_session']['id']}/rollback",
            json={},
        ).status_code == 200
        assert all(rule.id not in adapter.items for rule in rules)


def test_batch_delete_enters_one_recoverable_batch_and_restores_together(
    tmp_path: Path,
) -> None:
    with initialized_client(tmp_path) as (client, prefix, _store, adapter):
        rules = [
            FirewallRule(backend="ufw", port="9001", protocol="tcp"),
            FirewallRule(backend="ufw", port="9002", protocol="tcp"),
        ]
        adapter.items.update({rule.id: rule for rule in rules})
        prepared = client.post(
            f"{prefix}/api/v1/batch-delete",
            json={
                "rule_ids": [rule.id for rule in rules],
                "objects": [],
                "reason": "batch test",
            },
        )
        assert prepared.status_code == 200
        document = prepared.json()
        applied = client.post(
            f"{prefix}/api/v1/drafts/{document['draft']['id']}/confirm",
            json={"code": document["confirmation_code"]},
        )
        assert applied.status_code == 200
        delete_apply_id = applied.json()["apply_session"]["id"]
        assert all(rule.id not in adapter.items for rule in rules)
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{delete_apply_id}/confirm", json={}
        ).status_code == 200
        recycle = client.get(f"{prefix}/api/v1/recycle-bin").json()
        assert len(recycle) == 2
        assert len({item["batch_id"] for item in recycle}) == 1
        batch_id = recycle[0]["batch_id"]

        restored = client.post(
            f"{prefix}/api/v1/recycle-bin/batches/{batch_id}/restore", json={}
        )
        assert restored.status_code == 200
        restore_document = restored.json()
        restored_apply = client.post(
            f"{prefix}/api/v1/drafts/{restore_document['draft']['id']}/confirm",
            json={"code": restore_document["confirmation_code"]},
        )
        assert restored_apply.status_code == 200
        restore_apply_id = restored_apply.json()["apply_session"]["id"]
        assert all(rule.id in adapter.items for rule in rules)
        assert client.post(
            f"{prefix}/api/v1/apply-sessions/{restore_apply_id}/confirm", json={}
        ).status_code == 200
        assert client.get(f"{prefix}/api/v1/recycle-bin").json() == []
