from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .models import (
    BackendName,
    FirewallCapabilities,
    FirewallRule,
    FirewallStatus,
    RuleAction,
    ServiceAction,
    SystemProfile,
)
from .runner import CommandResult, CommandRunner


class FirewallError(RuntimeError):
    pass


class ReadOnlyBackendError(FirewallError):
    pass


@dataclass(slots=True)
class Detection:
    backend: BackendName
    active_backends: list[BackendName]
    installed_backends: list[BackendName]
    conflict: bool = False


def _is_active(runner: CommandRunner, backend: BackendName) -> bool:
    if backend == BackendName.FIREWALLD:
        result = runner.run(["firewall-cmd", "--state"], allowed_returncodes=(0, 252))
        return result.ok and result.stdout.strip() == "running"
    if backend == BackendName.UFW:
        result = runner.run(["ufw", "status"])
        return result.ok and "Status: active" in result.stdout
    if backend == BackendName.NFTABLES:
        result = runner.run(
            ["systemctl", "is-active", "nftables.service"],
            allowed_returncodes=(0, 3, 4),
        )
        return result.stdout.strip() == "active"
    if backend == BackendName.IPTABLES:
        for unit in ("iptables.service", "netfilter-persistent.service"):
            result = runner.run(
                ["systemctl", "is-active", unit], allowed_returncodes=(0, 3, 4)
            )
            if result.stdout.strip() == "active":
                return True
    return False


def detect_firewall(profile: SystemProfile, runner: CommandRunner) -> Detection:
    commands = {
        BackendName.FIREWALLD: "firewall-cmd",
        BackendName.UFW: "ufw",
        BackendName.NFTABLES: "nft",
        BackendName.IPTABLES: "iptables-save",
    }
    installed = [backend for backend, command in commands.items() if runner.exists(command)]
    active = [backend for backend in installed if _is_active(runner, backend)]
    if len(active) > 1:
        return Detection(BackendName.CONFLICT, active, installed, True)
    if len(active) == 1:
        return Detection(active[0], active, installed)

    family = {profile.os_id, *profile.os_like}
    preferences: list[BackendName]
    if family & {"rhel", "fedora", "centos", "rocky", "almalinux", "suse", "opensuse"}:
        preferences = [BackendName.FIREWALLD, BackendName.UFW, BackendName.NFTABLES]
    elif family & {"debian", "ubuntu"}:
        preferences = [BackendName.UFW, BackendName.FIREWALLD, BackendName.NFTABLES]
    else:
        preferences = [BackendName.FIREWALLD, BackendName.UFW, BackendName.NFTABLES]
    for backend in preferences:
        if backend in installed:
            return Detection(backend, [], installed)
    if BackendName.IPTABLES in installed:
        return Detection(BackendName.IPTABLES, [], installed)
    return Detection(BackendName.NONE, [], [])


class FirewallAdapter(ABC):
    backend: BackendName

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    @abstractmethod
    def status(self) -> FirewallStatus:
        raise NotImplementedError

    @abstractmethod
    def list_rules(self) -> list[FirewallRule]:
        raise NotImplementedError

    def apply_rule(self, operation: str, rule: FirewallRule, *, permanent: bool) -> None:
        raise ReadOnlyBackendError(f"{self.backend.value} 当前为只读后端")

    def service_action(self, action: ServiceAction) -> None:
        raise ReadOnlyBackendError(f"{self.backend.value} 不支持服务控制")


class UfwAdapter(FirewallAdapter):
    backend = BackendName.UFW
    SERVICE_UNITS = ("ufw.service",)

    def status(self) -> FirewallStatus:
        result = self.runner.run(["ufw", "status", "verbose"])
        active = result.ok and "Status: active" in result.stdout
        enabled = _systemd_enabled(self.runner, "ufw.service")
        default = "unknown"
        match = re.search(r"Default:\s+(\w+)\s+\(incoming\)", result.stdout)
        if match:
            default = match.group(1).lower()
        return FirewallStatus(
            backend=self.backend,
            active=active,
            enabled=enabled,
            service_unit="ufw.service",
            default_policy=default,
            capabilities=FirewallCapabilities(
                backend=self.backend,
                writable=True,
                service_actions=list(ServiceAction),
                features=[
                    "ports",
                    "services",
                    "sources",
                    "interfaces",
                    "routing",
                    "logging",
                    "ipv6",
                    "temporary-rules",
                ],
            ),
        )

    def list_rules(self) -> list[FirewallRule]:
        result = self.runner.run(["ufw", "status", "numbered"])
        if not result.ok:
            return []
        rules: list[FirewallRule] = []
        pattern = re.compile(
            r"^\[\s*(?P<num>\d+)\]\s+(?P<to>\S+)(?:\s+on\s+(?P<iface>\S+))?\s+"
            r"(?P<action>ALLOW|DENY|REJECT|LIMIT)(?:\s+(?P<direction>IN|OUT|FWD))?\s+"
            r"(?P<source>.+?)\s*$"
        )
        for line in result.stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            target = match.group("to")
            port: str | None = None
            protocol = "tcp"
            service: str | None = None
            if "/" in target:
                raw_port, raw_protocol = target.rsplit("/", 1)
                if raw_port.replace(":", "-").replace("-", "").isdigit():
                    port = raw_port
                    protocol = raw_protocol.lower()
                else:
                    service = target
            elif target.isdigit():
                port = target
            else:
                service = target
            action = match.group("action").lower()
            source = match.group("source").strip()
            if source.lower() in {"anywhere", "anywhere (v6)"}:
                source = None
            try:
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action=RuleAction(action),
                        direction=(match.group("direction") or "IN").lower().replace("fwd", "route"),
                        protocol=protocol if protocol in {"tcp", "udp", "sctp", "dccp"} else "tcp",
                        port=port,
                        service=service,
                        source=source,
                        interface_in=match.group("iface"),
                        metadata={"ufw_number": int(match.group("num")), "raw": line.strip()},
                    )
                )
            except ValueError:
                continue
        return rules

    @staticmethod
    def _rule_argv(rule: FirewallRule) -> list[str]:
        argv: list[str] = ["ufw"]
        if rule.direction == "route":
            argv.append("route")
        argv.append(rule.action.value)
        if rule.direction == "out":
            argv.append("out")
        elif rule.direction == "in":
            argv.append("in")
        if rule.interface_in:
            argv.extend(["on", rule.interface_in])
        if rule.source:
            argv.extend(["from", rule.source])
        else:
            argv.extend(["from", "any"])
        argv.extend(["to", rule.destination or "any"])
        if rule.port:
            argv.extend(["port", rule.port.replace("-", ":")])
        elif rule.service:
            argv.extend(["app", rule.service])
        if rule.protocol != "any":
            argv.extend(["proto", rule.protocol])
        if rule.comment:
            argv.extend(["comment", rule.comment])
        return argv

    def apply_rule(self, operation: str, rule: FirewallRule, *, permanent: bool) -> None:
        argv = self._rule_argv(rule)
        if operation == "delete":
            argv.insert(1, "--force")
            argv.insert(2, "delete")
        result = self.runner.run(argv)
        if not result.ok:
            raise FirewallError(result.stderr.strip() or result.stdout.strip() or "UFW 操作失败")

    def service_action(self, action: ServiceAction) -> None:
        if action in {ServiceAction.START, ServiceAction.ENABLE}:
            argv = ["ufw", "--force", "enable"]
        elif action in {ServiceAction.STOP, ServiceAction.DISABLE}:
            argv = ["ufw", "--force", "disable"]
        elif action in {ServiceAction.RESTART, ServiceAction.RELOAD}:
            argv = ["ufw", "reload"]
        else:
            raise FirewallError("不支持的 UFW 服务操作")
        result = self.runner.run(argv)
        if not result.ok:
            raise FirewallError(result.stderr.strip() or "UFW 服务操作失败")


class FirewalldAdapter(FirewallAdapter):
    backend = BackendName.FIREWALLD
    SERVICE_UNITS = ("firewalld.service",)

    def __init__(self, runner: CommandRunner, dbus_client: Any | None = None) -> None:
        super().__init__(runner)
        self.dbus = dbus_client

    def _ensure_dbus(self) -> Any:
        if self.dbus is None:
            from .firewalld_dbus import FirewalldDBus

            self.dbus = FirewalldDBus()
        return self.dbus

    def status(self) -> FirewallStatus:
        state = self.runner.run(
            ["systemctl", "is-active", "firewalld.service"],
            allowed_returncodes=(0, 3, 4),
        )
        enabled = _systemd_enabled(self.runner, "firewalld.service")
        version = self.runner.run(["firewall-cmd", "--version"]).stdout.strip()
        zones: list[str] = []
        default = "unknown"
        message = ""
        try:
            snapshot = self._ensure_dbus().snapshot()
            zones = sorted(snapshot.get("active_zones", {}).keys())
            default = snapshot.get("default_zone", "unknown")
        except Exception as exc:
            message = f"D-Bus 暂不可用：{exc}"
        return FirewallStatus(
            backend=self.backend,
            active=state.stdout.strip() == "active",
            enabled=enabled,
            version=version,
            service_unit="firewalld.service",
            default_policy=default,
            active_zones=zones,
            capabilities=FirewallCapabilities(
                backend=self.backend,
                writable=True,
                service_actions=list(ServiceAction),
                features=[
                    "zones",
                    "ports",
                    "services",
                    "sources",
                    "protocols",
                    "icmp",
                    "policies",
                    "ipsets",
                    "masquerade",
                    "forward-ports",
                    "rich-rules",
                    "runtime-permanent",
                ],
            ),
            message=message,
        )

    def list_rules(self) -> list[FirewallRule]:
        try:
            snapshot = self._ensure_dbus().snapshot()
        except Exception:
            return []
        rules: list[FirewallRule] = []
        for zone, settings in snapshot.get("zones", {}).items():
            for port, protocol in settings.get("ports", []):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        port=str(port),
                        protocol=str(protocol).lower(),
                        zone=zone,
                    )
                )
            for service in settings.get("services", []):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        service=service,
                        protocol="tcp",
                        zone=zone,
                    )
                )
            for rich_rule in settings.get("rich_rules", []):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        protocol="tcp",
                        zone=zone,
                        metadata={"rich_rule": rich_rule},
                    )
                )
            for source in settings.get("sources", []):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        protocol="tcp",
                        zone=zone,
                        metadata={"source_binding": source},
                    )
                )
            for protocol in settings.get("protocols", []):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        protocol="tcp",
                        zone=zone,
                        metadata={"protocol_binding": protocol},
                    )
                )
            for port, protocol in settings.get("source_ports", []):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        protocol=str(protocol).lower(),
                        zone=zone,
                        metadata={"source_port": str(port)},
                    )
                )
            for icmp_type in settings.get("icmp_blocks", []):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="deny",
                        protocol="tcp",
                        zone=zone,
                        metadata={"icmp_block": icmp_type},
                    )
                )
            if settings.get("masquerade"):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        protocol="tcp",
                        zone=zone,
                        metadata={"masquerade": True},
                    )
                )
            for forward in settings.get("forward_ports", []):
                if len(forward) < 4:
                    continue
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        protocol=str(forward[1]).lower(),
                        port=str(forward[0]),
                        zone=zone,
                        metadata={
                            "forward_port": {
                                "to_port": str(forward[2]),
                                "to_address": str(forward[3]),
                            }
                        },
                    )
                )
        return rules

    def apply_rule(self, operation: str, rule: FirewallRule, *, permanent: bool) -> None:
        dbus = self._ensure_dbus()
        method = "add" if operation in {"add", "restore"} else "remove"
        zone = rule.zone or dbus.default_zone()
        if rule.metadata.get("rich_rule"):
            dbus.change_rich_rule(zone, str(rule.metadata["rich_rule"]), method, permanent)
        elif rule.metadata.get("source_binding"):
            dbus.change_source(
                zone,
                str(rule.metadata["source_binding"]),
                method,
                permanent,
                rule.temporary_seconds,
            )
        elif rule.metadata.get("protocol_binding"):
            dbus.change_protocol(
                zone,
                str(rule.metadata["protocol_binding"]),
                method,
                permanent,
                rule.temporary_seconds,
            )
        elif rule.metadata.get("source_port"):
            dbus.change_source_port(
                zone,
                str(rule.metadata["source_port"]),
                rule.protocol,
                method,
                permanent,
                rule.temporary_seconds,
            )
        elif rule.metadata.get("icmp_block"):
            dbus.change_icmp_block(
                zone,
                str(rule.metadata["icmp_block"]),
                method,
                permanent,
                rule.temporary_seconds,
            )
        elif "masquerade" in rule.metadata:
            dbus.change_masquerade(
                zone, method, permanent, rule.temporary_seconds
            )
        elif rule.metadata.get("forward_port"):
            forward = rule.metadata["forward_port"]
            dbus.change_forward_port(
                zone,
                rule.port or "",
                rule.protocol,
                str(forward.get("to_port", "")),
                str(forward.get("to_address", "")),
                method,
                permanent,
                rule.temporary_seconds,
            )
        elif rule.port:
            dbus.change_port(zone, rule.port, rule.protocol, method, permanent, rule.temporary_seconds)
        elif rule.service:
            dbus.change_service(zone, rule.service, method, permanent, rule.temporary_seconds)
        else:
            raise FirewallError("无法识别 firewalld 规则类型")

    def service_action(self, action: ServiceAction) -> None:
        _systemd_action(self.runner, "firewalld.service", action)


class ReadOnlyAdapter(FirewallAdapter):
    def __init__(self, runner: CommandRunner, backend: BackendName) -> None:
        super().__init__(runner)
        self.backend = backend

    def status(self) -> FirewallStatus:
        unit = {
            BackendName.NFTABLES: "nftables.service",
            BackendName.IPTABLES: "iptables.service",
        }.get(self.backend, "")
        active = _is_active(self.runner, self.backend)
        return FirewallStatus(
            backend=self.backend,
            active=active,
            enabled=_systemd_enabled(self.runner, unit) if unit else None,
            service_unit=unit,
            capabilities=FirewallCapabilities(
                backend=self.backend,
                writable=False,
                service_actions=list(ServiceAction) if unit else [],
                features=["read-only-rules", "service-lifecycle"] if unit else ["read-only-rules"],
                reason="首版对原生 nftables/iptables 规则仅提供只读展示",
            ),
        )

    def list_rules(self) -> list[FirewallRule]:
        if self.backend == BackendName.NFTABLES:
            result = self.runner.run(["nft", "--json", "list", "ruleset"])
            if not result.ok:
                return []
            try:
                document = json.loads(result.stdout)
            except json.JSONDecodeError:
                return []
            rules: list[FirewallRule] = []
            for entry in document.get("nftables", []):
                if "rule" not in entry:
                    continue
                raw = entry["rule"]
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        service="nft-rule",
                        protocol="tcp",
                        metadata={"read_only": True, "native": raw},
                    )
                )
            return rules
        result = self.runner.run(["iptables-save"])
        rules = []
        for line in result.stdout.splitlines():
            if line.startswith("-A "):
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action="allow",
                        service="iptables-rule",
                        protocol="tcp",
                        metadata={"read_only": True, "native": line},
                    )
                )
        return rules

    def service_action(self, action: ServiceAction) -> None:
        unit = {
            BackendName.NFTABLES: "nftables.service",
            BackendName.IPTABLES: "iptables.service",
        }.get(self.backend)
        if not unit:
            raise ReadOnlyBackendError("没有可控制的服务单元")
        _systemd_action(self.runner, unit, action)


class ConflictAdapter(FirewallAdapter):
    backend = BackendName.CONFLICT

    def __init__(self, runner: CommandRunner, active: list[BackendName]) -> None:
        super().__init__(runner)
        self.active = active

    def status(self) -> FirewallStatus:
        return FirewallStatus(
            backend=self.backend,
            conflicts=[item.value for item in self.active],
            capabilities=FirewallCapabilities(
                backend=self.backend,
                writable=False,
                reason="检测到多个活动防火墙后端，必须先人工解决冲突",
            ),
            message="多个防火墙后端同时活动，WallPilot 已切换为只读模式。",
        )

    def list_rules(self) -> list[FirewallRule]:
        return []


def adapter_for(detection: Detection, runner: CommandRunner) -> FirewallAdapter:
    if detection.conflict:
        return ConflictAdapter(runner, detection.active_backends)
    if detection.backend == BackendName.FIREWALLD:
        return FirewalldAdapter(runner)
    if detection.backend == BackendName.UFW:
        return UfwAdapter(runner)
    return ReadOnlyAdapter(runner, detection.backend)


def _systemd_enabled(runner: CommandRunner, unit: str) -> bool | None:
    if not unit or not runner.exists("systemctl"):
        return None
    result = runner.run(["systemctl", "is-enabled", unit], allowed_returncodes=(0, 1, 3, 4))
    state = result.stdout.strip()
    if state in {"enabled", "enabled-runtime", "static"}:
        return True
    if state in {"disabled", "masked"}:
        return False
    return None


def _systemd_action(runner: CommandRunner, unit: str, action: ServiceAction) -> None:
    allowed_units = {
        "firewalld.service",
        "ufw.service",
        "nftables.service",
        "iptables.service",
        "ip6tables.service",
        "netfilter-persistent.service",
    }
    if unit not in allowed_units:
        raise FirewallError("拒绝控制非防火墙服务")
    argv = ["systemctl", action.value, unit]
    result: CommandResult = runner.run(argv, timeout=30)
    if not result.ok:
        raise FirewallError(result.stderr.strip() or f"{action.value} 操作失败")
