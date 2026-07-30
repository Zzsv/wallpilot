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

    def __init__(self) -> None:
        super().__init__(FakeRunner())
        self.items: dict[str, FirewallRule] = {}
        self.actions: list[str] = []

    def status(self) -> FirewallStatus:
        return FirewallStatus(
            backend=self.backend,
            active=True,
            enabled=True,
            service_unit="ufw.service",
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


@contextmanager
def initialized_client(
    tmp_path: Path,
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
    adapter = MemoryAdapter()
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
