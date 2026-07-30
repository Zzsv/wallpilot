from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import Settings
from .firewall import (
    FirewallAdapter,
    FirewallError,
    adapter_for,
    detect_firewall,
)
from .models import (
    BackendName,
    FirewallRule,
    ServerStatus,
    ServiceAction,
    SystemProfile,
)
from .runner import CommandRunner
from .storage import Store
from .system_info import (
    collect_containers,
    collect_failed_services,
    collect_listeners,
    collect_metrics,
    collect_profile,
    collect_security_services,
)


class ControlPlane:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        runner: CommandRunner | None = None,
        profile: SystemProfile | None = None,
        adapter: FirewallAdapter | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.runner = runner or CommandRunner()
        self.profile = profile or collect_profile()
        self.detection = detect_firewall(self.profile, self.runner)
        self._adapter_injected = adapter is not None
        self.adapter = adapter or adapter_for(self.detection, self.runner)

    def refresh_backend(self) -> None:
        if self._adapter_injected:
            return
        detection = detect_firewall(self.profile, self.runner)
        if detection.backend != self.detection.backend or detection.conflict != self.detection.conflict:
            self.detection = detection
            self.adapter = adapter_for(detection, self.runner)

    def firewall_status(self) -> dict[str, Any]:
        self.refresh_backend()
        return self.adapter.status().model_dump(mode="json")

    def rules(self) -> list[dict[str, Any]]:
        return [rule.model_dump(mode="json") for rule in self.adapter.list_rules()]

    def snapshot(self) -> dict[str, Any]:
        return {
            "created_at": datetime.now(UTC).isoformat(),
            "profile": self.profile.model_dump(mode="json"),
            "firewall": self.firewall_status(),
            "rules": self.rules(),
        }

    def server_status(self, *, persist_metrics: bool = False) -> dict[str, Any]:
        metrics = collect_metrics()
        firewall = self.adapter.status()
        listeners = collect_listeners(self.runner)
        status = ServerStatus(
            profile=self.profile,
            metrics=metrics,
            firewall=firewall,
            failed_services=collect_failed_services(self.runner),
            security_services=collect_security_services(self.runner),
            listeners=listeners,
            containers=collect_containers(self.runner),
            alerts=self._alerts(firewall.model_dump(mode="json"), listeners, metrics.model_dump()),
        )
        if persist_metrics:
            self.store.save_metrics(metrics.model_dump(mode="json"))
        return status.model_dump(mode="json")

    @staticmethod
    def _alerts(
        firewall: dict[str, Any],
        listeners: list[dict[str, str]],
        metrics: dict[str, Any],
    ) -> list[dict[str, str]]:
        alerts: list[dict[str, str]] = []
        if not firewall.get("active"):
            alerts.append(
                {"severity": "high", "title": "防火墙未运行", "detail": "服务器可能缺少本机入站保护。"}
            )
        if str(firewall.get("default_policy", "")).lower() in {"allow", "accept"}:
            alerts.append(
                {"severity": "warning", "title": "默认策略较宽松", "detail": "建议确认所有公网监听服务。"}
            )
        if firewall.get("conflicts"):
            alerts.append(
                {"severity": "high", "title": "多防火墙冲突", "detail": "写操作已被禁用。"}
            )
        total = int(metrics.get("memory_total", 0))
        available = int(metrics.get("memory_available", 0))
        if total and available / total < 0.1:
            alerts.append(
                {"severity": "warning", "title": "可用内存不足", "detail": "可用内存低于 10%。"}
            )
        for disk in metrics.get("disks", []):
            if disk.get("total") and disk.get("used", 0) / disk["total"] > 0.85:
                alerts.append(
                    {
                        "severity": "warning",
                        "title": "磁盘空间不足",
                        "detail": f"{disk.get('mount', '/')} 使用率超过 85%。",
                    }
                )
        sensitive = {21, 23, 2375, 3306, 5432, 6379, 9200, 27017}
        for listener in listeners:
            local = listener.get("local", "")
            try:
                port = int(local.rsplit(":", 1)[-1])
            except ValueError:
                continue
            if port in sensitive and (
                local.startswith("0.0.0.0:")
                or local.startswith("*:")
                or local.startswith("[::]:")
            ):
                alerts.append(
                    {
                        "severity": "high",
                        "title": f"敏感端口 {port} 监听所有地址",
                        "detail": listener.get("process") or "请核对对应服务和防火墙规则。",
                    }
                )
        return alerts

    def assess_rule_risk(self, operation: str, rule: FirewallRule) -> tuple[str, bool]:
        if operation == "delete" and (
            rule.port == "22" or (rule.service or "").lower() in {"ssh", "sshd"}
        ):
            return ("critical", True)
        if rule.direction == "route" or rule.metadata.get("masquerade"):
            return ("high", True)
        if operation == "add" and not rule.source and rule.port in {
            "3306",
            "5432",
            "6379",
            "9200",
            "27017",
        }:
            return ("high", True)
        return ("normal", False)

    def begin_rule_apply(
        self,
        draft: dict[str, Any],
        *,
        source: str,
    ) -> dict[str, Any]:
        payload = dict(draft["payload"])
        recycle_id = payload.pop("recycle_id", None)
        rule_payload = payload.get("rule", payload)
        rule = FirewallRule.model_validate(rule_payload)
        if rule.backend != self.adapter.backend:
            raise FirewallError("规则后端与当前活动防火墙不一致")
        operation = "add" if draft["operation"] == "restore" else draft["operation"]
        before = self.snapshot()
        self.store.create_backup(f"before-{draft['operation']}-{draft['id']}", before)
        self.adapter.apply_rule(operation, rule, permanent=False)
        inverse = "delete" if operation == "add" else "add"
        apply_session = self.store.create_apply_session(
            draft_id=draft["id"],
            kind="rule",
            operation=operation,
            payload={
                "rule": rule.model_dump(mode="json"),
                "source": source,
                "reason": draft.get("reason", ""),
                "object_type": draft.get("object_type", "rule"),
                "restore_recycle_id": recycle_id,
            },
            inverse_operation=inverse,
            before_snapshot=before,
            deadline=datetime.now(UTC)
            + timedelta(seconds=self.settings.apply_timeout_seconds),
            recycle_id=recycle_id,
        )
        self.store.audit(
            "rule.runtime_applied",
            "admin",
            source,
            {"apply_id": apply_session["id"], "operation": operation, "rule": rule.id},
        )
        return apply_session

    def confirm_apply(self, apply_id: str, source: str) -> dict[str, Any]:
        session = self.store.get_apply_session(apply_id)
        if not session or session["status"] != "pending":
            raise ValueError("应用会话不存在或已经结束")
        if datetime.fromisoformat(session["deadline"]) <= datetime.now(UTC):
            self.rollback_apply(apply_id, "confirmation-timeout")
            raise ValueError("确认时间已过，变更已经回滚")
        if session["kind"] == "rule":
            rule = FirewallRule.model_validate(session["payload"]["rule"])
            if self.adapter.backend == BackendName.FIREWALLD:
                self.adapter.apply_rule(session["operation"], rule, permanent=True)
            if session["operation"] == "delete":
                self.store.add_recycle_item(
                    backend=rule.backend.value,
                    system_version=f"{self.profile.os_name} {self.profile.os_version}".strip(),
                    object_type=session["payload"].get("object_type", "rule"),
                    object_name=rule.comment or rule.service or rule.port or rule.id,
                    fingerprint=rule.id,
                    payload=rule.model_dump(mode="json"),
                    dependencies=[],
                    runtime_before=session["before_snapshot"],
                    permanent_before=session["before_snapshot"],
                    source=session["payload"].get("source", source),
                    reason=session["payload"].get("reason", ""),
                )
            restore_id = session["payload"].get("restore_recycle_id")
            if restore_id:
                self.store.mark_recycle_restored(restore_id)
        self.store.set_apply_status(apply_id, "confirmed")
        if session.get("draft_id"):
            self.store.set_draft_status(session["draft_id"], "confirmed")
        self.store.audit("apply.confirmed", "admin", source, {"id": apply_id})
        return self.store.get_apply_session(apply_id) or {}

    def rollback_apply(self, apply_id: str, reason: str) -> None:
        session = self.store.get_apply_session(apply_id)
        if not session or session["status"] != "pending":
            return
        try:
            if session["kind"] == "rule":
                rule = FirewallRule.model_validate(session["payload"]["rule"])
                self.adapter.apply_rule(
                    session["inverse_operation"], rule, permanent=False
                )
            elif session["kind"] == "service":
                inverse = ServiceAction(session["inverse_operation"])
                self.adapter.service_action(inverse)
            self.store.set_apply_status(apply_id, "rolled_back")
            if session.get("draft_id"):
                self.store.set_draft_status(session["draft_id"], "rolled_back")
            self.store.audit(
                "apply.rolled_back", "wallpilot", "local", {"id": apply_id, "reason": reason}
            )
        except Exception as exc:
            self.store.set_apply_status(apply_id, "rollback_failed")
            self.store.audit(
                "apply.rollback_failed",
                "wallpilot",
                "local",
                {"id": apply_id, "reason": reason, "error": str(exc)},
            )
            raise

    def rollback_expired(self) -> list[str]:
        rolled_back: list[str] = []
        now = datetime.now(UTC)
        for session in self.store.pending_apply_sessions():
            if datetime.fromisoformat(session["deadline"]) <= now:
                self.rollback_apply(session["id"], "watchdog-timeout")
                rolled_back.append(session["id"])
        return rolled_back

    def service_action(
        self, action: ServiceAction, *, source: str
    ) -> dict[str, Any] | None:
        before = self.snapshot()
        self.store.create_backup(f"before-service-{action.value}", before)
        self.adapter.service_action(action)
        inverse_map = {
            ServiceAction.STOP: ServiceAction.START,
            ServiceAction.DISABLE: ServiceAction.ENABLE,
        }
        self.store.audit(
            "firewall.service_action",
            "admin",
            source,
            {"action": action.value, "backend": self.adapter.backend.value},
        )
        if action not in inverse_map:
            return None
        return self.store.create_apply_session(
            draft_id=None,
            kind="service",
            operation=action.value,
            payload={"backend": self.adapter.backend.value},
            inverse_operation=inverse_map[action].value,
            before_snapshot=before,
            deadline=datetime.now(UTC)
            + timedelta(seconds=self.settings.apply_timeout_seconds),
        )

    def emergency_start(self) -> None:
        self.refresh_backend()
        self.adapter.service_action(ServiceAction.START)
        self.store.audit("firewall.emergency_start", "local-admin", "local", {})

    def emergency_rollback(self) -> list[str]:
        rolled: list[str] = []
        for session in self.store.pending_apply_sessions():
            self.rollback_apply(session["id"], "manual-emergency")
            rolled.append(session["id"])
        return rolled

    @property
    def hostname(self) -> str:
        return self.profile.hostname or socket.gethostname()
