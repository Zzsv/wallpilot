from __future__ import annotations

import socket
import re
import uuid
import ipaddress
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
    FirewallObject,
    FirewallRule,
    ServerStatus,
    ServiceAction,
    SystemProfile,
)
from .runner import CommandRunner
from .storage import Store
from .system_info import (
    collect_containers,
    collect_connections,
    collect_default_routes,
    collect_dns_servers,
    collect_failed_services,
    collect_listeners,
    collect_metrics,
    collect_network_interfaces,
    collect_profile,
    collect_security_modules,
    collect_security_update_cache,
    collect_security_services,
    collect_ssh_sessions,
    reboot_required,
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
        self.adapter = adapter or adapter_for(
            self.detection, self.runner, systemd=self.profile.systemd
        )

    def refresh_backend(self) -> None:
        if self._adapter_injected:
            return
        detection = detect_firewall(self.profile, self.runner)
        if detection.backend != self.detection.backend or detection.conflict != self.detection.conflict:
            self.detection = detection
            self.adapter = adapter_for(
                detection, self.runner, systemd=self.profile.systemd
            )

    def firewall_status(self) -> dict[str, Any]:
        self.refresh_backend()
        return self.adapter.status().model_dump(mode="json")

    def rules(self) -> list[dict[str, Any]]:
        return [rule.model_dump(mode="json") for rule in self.adapter.list_rules()]

    def rule_conflicts(self, candidate: FirewallRule) -> dict[str, list[str]]:
        duplicates: list[str] = []
        conflicts: list[str] = []
        for current in self.adapter.list_rules():
            if current.id == candidate.id:
                duplicates.append(current.id)
                continue
            if (
                current.backend != candidate.backend
                or current.direction != candidate.direction
                or current.protocol != candidate.protocol
                or current.port != candidate.port
                or current.service != candidate.service
                or (current.zone or "") != (candidate.zone or "")
            ):
                continue
            if current.source and candidate.source:
                if not ipaddress.ip_network(current.source).overlaps(
                    ipaddress.ip_network(candidate.source)
                ):
                    continue
            if current.action != candidate.action:
                conflicts.append(current.id)
        return {"duplicates": duplicates, "conflicts": conflicts}

    def objects(self) -> list[dict[str, Any]]:
        return self.adapter.list_objects()

    def rejection_logs(self, limit: int = 200) -> list[str]:
        return self.adapter.rejection_logs(limit)

    def get_object(self, object_type: str, name: str) -> dict[str, Any]:
        return self.adapter.get_object(object_type, name).model_dump(mode="json")

    def object_dependencies(self, item: FirewallObject) -> list[dict[str, str]]:
        dependencies: list[dict[str, str]] = []
        for service in item.settings.get("services", []):
            dependencies.append(
                {
                    "type": "service",
                    "name": str(service),
                    "relation": "requires-service",
                }
            )
        if item.object_type == "policy":
            for zone in (
                item.settings.get("ingress_zones", [])
                + item.settings.get("egress_zones", [])
            ):
                if zone not in {"HOST", "ANY"}:
                    dependencies.append(
                        {
                            "type": "zone",
                            "name": str(zone),
                            "relation": "requires-zone",
                        }
                    )
        for rich in item.settings.get("rich_rules", []):
            for name in re.findall(
                r'ipset\s*=\s*"([A-Za-z][A-Za-z0-9_-]{0,63})"', rich
            ):
                dependencies.append(
                    {
                        "type": "ipset",
                        "name": name,
                        "relation": "requires-ipset",
                    }
                )
        for rule in self.adapter.list_rules():
            if item.object_type == "zone" and rule.zone == item.name:
                dependencies.append(
                    {"type": "rule", "name": rule.id, "relation": "uses-zone"}
                )
            if item.object_type == "service" and rule.service == item.name:
                dependencies.append(
                    {"type": "rule", "name": rule.id, "relation": "uses-service"}
                )
        for summary in self.adapter.list_objects():
            key = (str(summary.get("object_type")), str(summary.get("name")))
            if key == (item.object_type, item.name):
                continue
            possible_referrers = {
                "service": {"zone", "policy"},
                "zone": {"policy"},
                "ipset": {"zone", "policy"},
                "policy": set(),
            }[item.object_type]
            if key[0] not in possible_referrers:
                continue
            try:
                other = self.adapter.get_object(*key)
            except Exception:
                continue
            settings = other.settings
            relation = ""
            if item.object_type == "service" and item.name in settings.get(
                "services", []
            ):
                relation = "uses-service"
            elif item.object_type == "zone" and item.name in (
                settings.get("ingress_zones", [])
                + settings.get("egress_zones", [])
            ):
                relation = "uses-zone"
            elif item.object_type == "ipset" and any(
                item.name in rich
                for rich in settings.get("rich_rules", [])
            ):
                relation = "uses-ipset"
            if relation:
                dependencies.append(
                    {
                        "type": other.object_type,
                        "name": other.name,
                        "relation": relation,
                    }
                )
        unique: dict[tuple[str, str, str], dict[str, str]] = {}
        for dependency in dependencies:
            key = (
                dependency["type"],
                dependency["name"],
                dependency["relation"],
            )
            unique[key] = dependency
        return list(unique.values())

    def snapshot(self) -> dict[str, Any]:
        return {
            "created_at": datetime.now(UTC).isoformat(),
            "profile": self.profile.model_dump(mode="json"),
            "firewall": self.firewall_status(),
            "rules": self.rules(),
        }

    def export_configuration(self) -> dict[str, Any]:
        objects: list[dict[str, Any]] = []
        for summary in self.objects():
            if summary.get("builtin"):
                continue
            try:
                objects.append(
                    self.get_object(
                        str(summary["object_type"]), str(summary["name"])
                    )
                )
            except Exception:
                continue
        return {
            "format": "wallpilot-config",
            "version": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "backend": self.adapter.backend.value,
            "rules": self.rules(),
            "objects": objects,
        }

    def prepare_import(
        self,
        rules: list[FirewallRule],
        objects: list[FirewallObject],
    ) -> dict[str, Any]:
        if not rules and not objects:
            raise ValueError("导入文件没有规则或高级对象")
        existing_rules = {rule["id"] for rule in self.rules()}
        pending_rules: list[FirewallRule] = []
        skipped: list[str] = []
        seen_rules: set[str] = set()
        risk = "normal"
        requires_totp = False
        risk_order = {"normal": 0, "high": 1, "critical": 2}
        for rule in rules:
            if rule.backend != self.adapter.backend:
                raise ValueError("导入规则的后端与当前活动防火墙不一致")
            if rule.id in existing_rules or rule.id in seen_rules:
                skipped.append(f"rule:{rule.id}")
                continue
            seen_rules.add(rule.id)
            pending_rules.append(rule)
            item_risk, item_totp = self.assess_rule_risk("add", rule)
            if risk_order[item_risk] > risk_order[risk]:
                risk = item_risk
            requires_totp = requires_totp or item_totp

        existing_objects = {
            (str(item["object_type"]), str(item["name"])): item
            for item in self.objects()
        }
        pending_objects: list[FirewallObject] = []
        seen_objects: dict[tuple[str, str], FirewallObject] = {}
        for item in objects:
            if item.backend != self.adapter.backend:
                raise ValueError("导入对象的后端与当前活动防火墙不一致")
            if item.builtin:
                raise ValueError("导入文件不能创建或覆盖内置对象")
            key = (item.object_type, item.name)
            if key in seen_objects:
                if seen_objects[key].settings != item.settings:
                    raise ValueError(f"导入文件含有冲突的同名对象：{item.name}")
                skipped.append(f"{item.object_type}:{item.name}")
                continue
            seen_objects[key] = item
            if key in existing_objects:
                current = FirewallObject.model_validate(
                    self.get_object(item.object_type, item.name)
                )
                if current.settings != item.settings:
                    raise ValueError(f"同名对象内容不同，拒绝覆盖：{item.name}")
                skipped.append(f"{item.object_type}:{item.name}")
                continue
            pending_objects.append(item)
            item_risk, item_totp = self.assess_object_risk("add", item)
            if risk_order[item_risk] > risk_order[risk]:
                risk = item_risk
            requires_totp = requires_totp or item_totp
        if not pending_rules and not pending_objects:
            raise ValueError("导入内容已经全部存在，无需重复添加")
        return {
            "rules": [rule.model_dump(mode="json") for rule in pending_rules],
            "objects": [item.model_dump(mode="json") for item in pending_objects],
            "skipped": skipped,
            "risk": risk,
            "requires_totp": requires_totp,
        }

    def prepare_delete_batch(
        self,
        rule_ids: list[str],
        object_refs: list[tuple[str, str]],
    ) -> dict[str, Any]:
        current_rules = {rule.id: rule for rule in self.adapter.list_rules()}
        rules: list[FirewallRule] = []
        for rule_id in dict.fromkeys(rule_ids):
            if rule_id not in current_rules:
                raise ValueError(f"规则不存在或已经改变：{rule_id}")
            rules.append(current_rules[rule_id])
        objects: list[FirewallObject] = []
        for object_type, name in dict.fromkeys(object_refs):
            item = self.adapter.get_object(object_type, name)
            if item.builtin:
                raise ValueError(f"内置对象不能删除：{object_type}:{name}")
            objects.append(item)
        if not rules and not objects:
            raise ValueError("没有选择要删除的规则或对象")
        risk = "normal"
        requires_totp = False
        risk_order = {"normal": 0, "high": 1, "critical": 2}
        for rule in rules:
            item_risk, item_totp = self.assess_rule_risk("delete", rule)
            if risk_order[item_risk] > risk_order[risk]:
                risk = item_risk
            requires_totp = requires_totp or item_totp
        for item in objects:
            item_risk, item_totp = self.assess_object_risk("delete", item)
            if risk_order[item_risk] > risk_order[risk]:
                risk = item_risk
            requires_totp = requires_totp or item_totp
        return {
            "rules": [rule.model_dump(mode="json") for rule in rules],
            "objects": [item.model_dump(mode="json") for item in objects],
            "batch_id": str(uuid.uuid4()),
            "risk": risk,
            "requires_totp": requires_totp,
        }

    def server_status(self, *, persist_metrics: bool = False) -> dict[str, Any]:
        metrics = collect_metrics()
        firewall = self.adapter.status()
        listeners = collect_listeners(self.runner)
        rules = self.adapter.list_rules()
        containers = collect_containers(self.runner)
        security_services = collect_security_services(self.runner)
        self._associate_listeners(
            listeners, rules, containers, security_services
        )
        status = ServerStatus(
            profile=self.profile,
            metrics=metrics,
            firewall=firewall,
            failed_services=collect_failed_services(self.runner),
            security_services=security_services,
            security_modules=collect_security_modules(self.runner),
            security_updates=collect_security_update_cache(),
            listeners=listeners,
            connections=collect_connections(self.runner),
            network_interfaces=collect_network_interfaces(self.runner),
            default_routes=collect_default_routes(self.runner),
            dns_servers=collect_dns_servers(),
            ssh_sessions=collect_ssh_sessions(self.runner),
            containers=containers,
            reboot_required=reboot_required(),
            alerts=self._alerts(
                firewall.model_dump(mode="json"),
                listeners,
                metrics.model_dump(),
                [rule.model_dump(mode="json") for rule in rules],
            ),
        )
        if persist_metrics:
            self.store.save_metrics(metrics.model_dump(mode="json"))
        return status.model_dump(mode="json")

    @staticmethod
    def _associate_listeners(
        listeners: list[dict[str, str]],
        rules: list[FirewallRule],
        containers: list[dict[str, str]],
        services: dict[str, str],
    ) -> None:
        for listener in listeners:
            try:
                port = int(listener.get("local", "").rsplit(":", 1)[-1])
            except ValueError:
                continue
            related_rules: list[str] = []
            for rule in rules:
                if not rule.port:
                    continue
                bounds = [int(value) for value in rule.port.split("-")]
                if bounds[0] <= port <= bounds[-1]:
                    related_rules.append(rule.id)
            related_containers = [
                container["name"]
                for container in containers
                if re.search(
                    rf"(?:^|[:\s]){port}(?:->|/|$)",
                    container.get("ports", ""),
                )
            ]
            process = listener.get("process", "").lower()
            related_service = next(
                (
                    unit
                    for unit in services
                    if unit.removesuffix(".service").replace("sshd", "ssh")
                    in process.replace("sshd", "ssh")
                ),
                "",
            )
            listener["firewall_rules"] = ",".join(related_rules)
            listener["containers"] = ",".join(related_containers)
            listener["service"] = related_service

    @staticmethod
    def _alerts(
        firewall: dict[str, Any],
        listeners: list[dict[str, str]],
        metrics: dict[str, Any],
        rules: list[dict[str, Any]],
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
            if (
                not listener.get("process")
                and (
                    local.startswith("0.0.0.0:")
                    or local.startswith("*:")
                    or local.startswith("[::]:")
                )
            ):
                alerts.append(
                    {
                        "severity": "warning",
                        "title": f"未知进程监听公网端口 {port}",
                        "detail": "无法关联到进程，请在服务器上核对该监听端口。",
                    }
                )
        for rule in rules:
            if rule.get("action") != "allow" or rule.get("source"):
                continue
            label = str(rule.get("service") or rule.get("port") or "")
            if label.lower() in {"22", "ssh", "sshd"}:
                alerts.append(
                    {
                        "severity": "high",
                        "title": "SSH 来源范围过宽",
                        "detail": "允许任意来源访问 SSH，建议限制为管理网段。",
                    }
                )
            if label in {"3306", "5432", "6379", "9200", "27017"}:
                alerts.append(
                    {
                        "severity": "high",
                        "title": f"数据库端口 {label} 对任意来源开放",
                        "detail": "建议限制来源地址或关闭不必要的公网访问。",
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
        if (
            operation in {"add", "restore"}
            and not rule.source
            and rule.port
            in {
                "22",
            "3306",
            "5432",
            "6379",
            "9200",
            "27017",
            }
        ):
            return ("high", True)
        return ("normal", False)

    @staticmethod
    def assess_object_risk(
        operation: str, item: FirewallObject
    ) -> tuple[str, bool]:
        if item.builtin and operation in {"delete", "update"}:
            return ("blocked", True)
        if operation == "delete" or item.object_type in {"zone", "policy"}:
            return ("high", True)
        if operation == "update":
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

    def begin_object_apply(
        self,
        draft: dict[str, Any],
        *,
        source: str,
    ) -> dict[str, Any]:
        payload = dict(draft["payload"])
        recycle_id = payload.pop("recycle_id", None)
        item = FirewallObject.model_validate(payload.get("object", payload))
        before_raw = payload.get("before")
        before = FirewallObject.model_validate(before_raw) if before_raw else None
        if item.backend != self.adapter.backend:
            raise FirewallError("对象后端与当前活动防火墙不一致")
        operation = "add" if draft["operation"] == "restore" else draft["operation"]
        if operation in {"delete", "update"}:
            current = self.adapter.get_object(item.object_type, item.name)
            if current.builtin:
                raise FirewallError("内置对象不能删除或覆盖")
            before = current
            if operation == "delete":
                item = current
        dependencies = (
            self.object_dependencies(item) if operation == "delete" else []
        )
        snapshot = self.snapshot()
        self.store.create_backup(
            f"before-{draft['operation']}-{item.object_type}-{item.name}", snapshot
        )
        self.adapter.apply_object(operation, item, before=before)
        inverse = {
            "add": "delete",
            "delete": "add",
            "update": "update",
        }[operation]
        return self.store.create_apply_session(
            draft_id=draft["id"],
            kind="object",
            operation=operation,
            payload={
                "object": item.model_dump(mode="json"),
                "before": before.model_dump(mode="json") if before else None,
                "source": source,
                "reason": draft.get("reason", ""),
                "dependencies": dependencies,
                "restore_recycle_id": recycle_id,
            },
            inverse_operation=inverse,
            before_snapshot=snapshot,
            deadline=datetime.now(UTC)
            + timedelta(seconds=self.settings.apply_timeout_seconds),
            recycle_id=recycle_id,
        )

    def begin_batch_apply(
        self,
        draft: dict[str, Any],
        *,
        source: str,
    ) -> dict[str, Any]:
        payload = draft["payload"]
        operation = str(draft.get("operation", "add"))
        if operation == "restore":
            operation = "add"
        if operation not in {"add", "delete"}:
            raise FirewallError("批量草稿操作不受支持")
        rules = [
            FirewallRule.model_validate(value) for value in payload.get("rules", [])
        ]
        object_order = {"ipset": 0, "service": 1, "zone": 2, "policy": 3}
        objects = sorted(
            [
                FirewallObject.model_validate(value)
                for value in payload.get("objects", [])
            ],
            key=lambda item: object_order[item.object_type],
        )
        if not rules and not objects:
            raise FirewallError("批量草稿不包含可应用的配置")
        if any(rule.backend != self.adapter.backend for rule in rules) or any(
            item.backend != self.adapter.backend for item in objects
        ):
            raise FirewallError("批量草稿后端与当前活动防火墙不一致")
        if operation == "delete":
            rules_by_id = {
                rule.id: rule for rule in self.adapter.list_rules()
            }
            try:
                rules = [rules_by_id[rule.id] for rule in rules]
            except KeyError as exc:
                raise FirewallError("批量删除中的规则已经改变") from exc
            live_objects: list[FirewallObject] = []
            for item in objects:
                current = self.adapter.get_object(item.object_type, item.name)
                if current.builtin:
                    raise FirewallError("内置对象不能批量删除")
                live_objects.append(current)
            objects = live_objects
        snapshot = self.snapshot()
        self.store.create_backup(
            f"before-batch-{operation}-{draft['id']}", snapshot
        )
        applied_rules: list[FirewallRule] = []
        applied_objects: list[FirewallObject] = []
        object_dependencies = {
            f"{item.object_type}:{item.name}": self.object_dependencies(item)
            for item in objects
        }
        try:
            if operation == "add":
                for item in objects:
                    self.adapter.apply_object("add", item)
                    applied_objects.append(item)
                for rule in rules:
                    self.adapter.apply_rule("add", rule, permanent=False)
                    applied_rules.append(rule)
            else:
                for rule in rules:
                    self.adapter.apply_rule("delete", rule, permanent=False)
                    applied_rules.append(rule)
                delete_order = {"policy": 0, "zone": 1, "service": 2, "ipset": 3}
                for item in sorted(
                    objects, key=lambda value: delete_order[value.object_type]
                ):
                    self.adapter.apply_object("delete", item)
                    applied_objects.append(item)
        except Exception:
            if operation == "add":
                for rule in reversed(applied_rules):
                    try:
                        self.adapter.apply_rule("delete", rule, permanent=False)
                    except Exception:
                        pass
                for item in reversed(applied_objects):
                    try:
                        self.adapter.apply_object("delete", item)
                    except Exception:
                        pass
            else:
                for item in sorted(
                    applied_objects,
                    key=lambda value: object_order[value.object_type],
                ):
                    try:
                        self.adapter.apply_object("add", item)
                    except Exception:
                        pass
                for rule in applied_rules:
                    try:
                        self.adapter.apply_rule("add", rule, permanent=False)
                    except Exception:
                        pass
            raise
        apply_session = self.store.create_apply_session(
            draft_id=draft["id"],
            kind="batch",
            operation=operation,
            payload={
                "rules": [rule.model_dump(mode="json") for rule in rules],
                "objects": [item.model_dump(mode="json") for item in objects],
                "source": source,
                "reason": draft.get("reason", ""),
                "batch_id": payload.get("batch_id"),
                "object_dependencies": object_dependencies,
                "restore_recycle_ids": payload.get(
                    "restore_recycle_ids", []
                ),
            },
            inverse_operation="delete" if operation == "add" else "add",
            before_snapshot=snapshot,
            deadline=datetime.now(UTC)
            + timedelta(seconds=self.settings.apply_timeout_seconds),
        )
        self.store.audit(
            "batch.runtime_applied",
            "admin",
            source,
            {
                "apply_id": apply_session["id"],
                "rules": len(rules),
                "objects": len(objects),
                "operation": operation,
            },
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
            if (
                self.adapter.backend == BackendName.FIREWALLD
                and rule.temporary_seconds == 0
            ):
                try:
                    self.adapter.apply_rule(
                        session["operation"], rule, permanent=True
                    )
                except Exception:
                    inverse = (
                        "delete"
                        if session["operation"] == "add"
                        else "add"
                    )
                    try:
                        self.adapter.apply_rule(
                            inverse, rule, permanent=True
                        )
                    except Exception:
                        pass
                    self.rollback_apply(apply_id, "persistence-failed")
                    raise
            if (
                session["operation"] == "add"
                and rule.temporary_seconds > 0
                and self.adapter.backend == BackendName.UFW
            ):
                self.store.schedule_temporary_rule(
                    rule.id,
                    rule.backend.value,
                    rule.model_dump(mode="json"),
                    datetime.now(UTC) + timedelta(seconds=rule.temporary_seconds),
                )
            if session["operation"] == "delete":
                self.store.add_recycle_item(
                    backend=rule.backend.value,
                    system_version=f"{self.profile.os_name} {self.profile.os_version}".strip(),
                    object_type=session["payload"].get("object_type", "rule"),
                    object_name=rule.comment or rule.service or rule.port or rule.id,
                    fingerprint=rule.id,
                    payload=rule.model_dump(mode="json"),
                    dependencies=session["payload"].get("dependencies", []),
                    runtime_before=session["before_snapshot"],
                    permanent_before=session["before_snapshot"],
                    source=session["payload"].get("source", source),
                    reason=session["payload"].get("reason", ""),
                )
            restore_id = session["payload"].get("restore_recycle_id")
            if restore_id:
                self.store.mark_recycle_restored(restore_id)
        elif session["kind"] == "object":
            item = FirewallObject.model_validate(session["payload"]["object"])
            if session["operation"] == "delete":
                self.store.add_recycle_item(
                    backend=item.backend.value,
                    system_version=f"{self.profile.os_name} {self.profile.os_version}".strip(),
                    object_type=item.object_type,
                    object_name=item.name,
                    fingerprint=item.id,
                    payload=item.model_dump(mode="json"),
                    dependencies=session["payload"].get("dependencies", []),
                    runtime_before=session["before_snapshot"],
                    permanent_before=session["before_snapshot"],
                    source=session["payload"].get("source", source),
                    reason=session["payload"].get("reason", ""),
                )
            restore_id = session["payload"].get("restore_recycle_id")
            if restore_id:
                self.store.mark_recycle_restored(restore_id)
        elif session["kind"] == "batch":
            rules = [
                FirewallRule.model_validate(raw)
                for raw in session["payload"].get("rules", [])
            ]
            objects = [
                FirewallObject.model_validate(raw)
                for raw in session["payload"].get("objects", [])
            ]
            if session["operation"] == "add":
                persisted: list[FirewallRule] = []
                try:
                    for rule in rules:
                        if (
                            self.adapter.backend == BackendName.FIREWALLD
                            and rule.temporary_seconds == 0
                        ):
                            self.adapter.apply_rule(
                                "add", rule, permanent=True
                            )
                            persisted.append(rule)
                        elif (
                            self.adapter.backend == BackendName.UFW
                            and rule.temporary_seconds > 0
                        ):
                            self.store.schedule_temporary_rule(
                                rule.id,
                                rule.backend.value,
                                rule.model_dump(mode="json"),
                                datetime.now(UTC)
                                + timedelta(seconds=rule.temporary_seconds),
                            )
                except Exception:
                    for persisted_rule in reversed(persisted):
                        try:
                            self.adapter.apply_rule(
                                "delete", persisted_rule, permanent=True
                            )
                        except Exception:
                            pass
                    self.rollback_apply(apply_id, "persistence-failed")
                    raise
                for recycle_id in session["payload"].get(
                    "restore_recycle_ids", []
                ):
                    self.store.mark_recycle_restored(str(recycle_id))
            else:
                batch_id = str(session["payload"].get("batch_id") or uuid.uuid4())
                persisted = []
                try:
                    for rule in rules:
                        if self.adapter.backend == BackendName.FIREWALLD:
                            self.adapter.apply_rule(
                                "delete", rule, permanent=True
                            )
                            persisted.append(rule)
                except Exception:
                    for persisted_rule in reversed(persisted):
                        try:
                            self.adapter.apply_rule(
                                "add", persisted_rule, permanent=True
                            )
                        except Exception:
                            pass
                    self.rollback_apply(apply_id, "persistence-failed")
                    raise
                for rule in rules:
                    self.store.add_recycle_item(
                        backend=rule.backend.value,
                        system_version=(
                            f"{self.profile.os_name} "
                            f"{self.profile.os_version}"
                        ).strip(),
                        object_type="rule",
                        object_name=(
                            rule.comment
                            or rule.service
                            or rule.port
                            or rule.id
                        ),
                        fingerprint=rule.id,
                        payload=rule.model_dump(mode="json"),
                        dependencies=[],
                        runtime_before=session["before_snapshot"],
                        permanent_before=session["before_snapshot"],
                        source=session["payload"].get("source", source),
                        reason=session["payload"].get("reason", ""),
                        batch_id=batch_id,
                    )
                dependency_map = session["payload"].get(
                    "object_dependencies", {}
                )
                for item in objects:
                    self.store.add_recycle_item(
                        backend=item.backend.value,
                        system_version=(
                            f"{self.profile.os_name} "
                            f"{self.profile.os_version}"
                        ).strip(),
                        object_type=item.object_type,
                        object_name=item.name,
                        fingerprint=item.id,
                        payload=item.model_dump(mode="json"),
                        dependencies=dependency_map.get(
                            f"{item.object_type}:{item.name}", []
                        ),
                        runtime_before=session["before_snapshot"],
                        permanent_before=session["before_snapshot"],
                        source=session["payload"].get("source", source),
                        reason=session["payload"].get("reason", ""),
                        batch_id=batch_id,
                    )
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
            elif session["kind"] == "object":
                item = FirewallObject.model_validate(session["payload"]["object"])
                before_raw = session["payload"].get("before")
                before = (
                    FirewallObject.model_validate(before_raw) if before_raw else None
                )
                inverse = session["inverse_operation"]
                if inverse == "delete":
                    self.adapter.apply_object("delete", item)
                elif inverse == "add":
                    self.adapter.apply_object("add", before or item)
                elif inverse == "update":
                    if before is None:
                        raise FirewallError("缺少高级对象回滚快照")
                    self.adapter.apply_object("update", before, before=item)
            elif session["kind"] == "batch":
                rules = [
                    FirewallRule.model_validate(raw)
                    for raw in session["payload"].get("rules", [])
                ]
                objects = [
                    FirewallObject.model_validate(raw)
                    for raw in session["payload"].get("objects", [])
                ]
                if session["operation"] == "add":
                    for rule in reversed(rules):
                        self.adapter.apply_rule(
                            "delete", rule, permanent=False
                        )
                    for item in reversed(objects):
                        self.adapter.apply_object("delete", item)
                else:
                    object_order = {
                        "ipset": 0,
                        "service": 1,
                        "zone": 2,
                        "policy": 3,
                    }
                    for item in sorted(
                        objects,
                        key=lambda value: object_order[value.object_type],
                    ):
                        self.adapter.apply_object("add", item)
                    for rule in rules:
                        self.adapter.apply_rule(
                            "add", rule, permanent=False
                        )
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

    def expire_temporary_rules(self) -> list[str]:
        expired: list[str] = []
        for scheduled in self.store.due_temporary_rules():
            rule_id = str(scheduled["id"])
            try:
                rule = FirewallRule.model_validate(scheduled["payload"])
                if rule.backend != self.adapter.backend:
                    raise FirewallError("临时规则后端与当前活动防火墙不一致")
                self.adapter.apply_rule("delete", rule, permanent=False)
                self.store.set_temporary_rule_status(rule_id, "expired")
                self.store.audit(
                    "rule.temporary_expired",
                    "wallpilot",
                    "local",
                    {"rule": rule_id, "backend": rule.backend.value},
                )
                expired.append(rule_id)
            except Exception as exc:
                self.store.set_temporary_rule_status(rule_id, "expiration_failed")
                self.store.audit(
                    "rule.temporary_expiration_failed",
                    "wallpilot",
                    "local",
                    {"rule": rule_id, "error": str(exc)},
                )
        return expired

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
