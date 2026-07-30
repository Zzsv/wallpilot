from __future__ import annotations

import ipaddress
import json
import pathlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .models import (
    BackendName,
    FirewallCapabilities,
    FirewallObject,
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
        rules = runner.run(["nft", "--json", "list", "ruleset"])
        if rules.ok:
            try:
                document = json.loads(rules.stdout)
                if any(
                    key in entry
                    for entry in document.get("nftables", [])
                    for key in ("rule", "chain", "table")
                ):
                    return True
            except json.JSONDecodeError:
                pass
        result = runner.run(
            ["systemctl", "is-active", "nftables.service"],
            allowed_returncodes=(0, 3, 4),
        )
        return result.stdout.strip() == "active"
    if backend == BackendName.IPTABLES:
        rules = runner.run(["iptables-save"])
        if rules.ok and any(
            line.startswith("-A ") for line in rules.stdout.splitlines()
        ):
            return True
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
    managed = [
        backend
        for backend in (BackendName.FIREWALLD, BackendName.UFW)
        if backend in installed and _is_active(runner, backend)
    ]
    active = managed or [
        backend
        for backend in (BackendName.NFTABLES, BackendName.IPTABLES)
        if backend in installed and _is_active(runner, backend)
    ]
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

    def list_objects(self) -> list[dict[str, Any]]:
        return []

    def rejection_logs(self, limit: int = 200) -> list[str]:
        return []

    def get_object(self, object_type: str, name: str) -> FirewallObject:
        raise ReadOnlyBackendError(f"{self.backend.value} 不支持高级对象")

    def apply_object(
        self,
        operation: str,
        item: FirewallObject,
        *,
        before: FirewallObject | None = None,
    ) -> None:
        raise ReadOnlyBackendError(f"{self.backend.value} 不支持高级对象")


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
            r"^\[\s*(?P<num>\d+)\]\s+(?P<to>\S+)(?:\s+\(v6\))?"
            r"(?:\s+on\s+(?P<iface>\S+))?\s+"
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
            comment = ""
            if " # " in source:
                source, comment = source.split(" # ", 1)
                source = source.strip()
                comment = comment.strip()
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
                        comment=comment,
                        metadata={"ufw_number": int(match.group("num")), "raw": line.strip()},
                    )
                )
            except ValueError:
                continue
        unique: dict[str, FirewallRule] = {}
        for rule in rules:
            unique.setdefault(rule.id, rule)
        return list(unique.values())

    @staticmethod
    def _rule_argv(rule: FirewallRule) -> list[str]:
        argv: list[str] = ["ufw"]
        if rule.direction == "route":
            argv.append("route")
        argv.append(rule.action.value)
        if rule.direction == "route":
            if rule.interface_in:
                argv.extend(["in", "on", rule.interface_in])
            if rule.interface_out:
                argv.extend(["out", "on", rule.interface_out])
        elif rule.direction == "out":
            argv.append("out")
            interface = rule.interface_out or rule.interface_in
            if interface:
                argv.extend(["on", interface])
        else:
            argv.append("in")
            if rule.interface_in:
                argv.extend(["on", rule.interface_in])
        if rule.log != "off":
            argv.append(rule.log)
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

    def rejection_logs(self, limit: int = 200) -> list[str]:
        if not self.runner.exists("journalctl"):
            return []
        result = self.runner.run(
            [
                "journalctl",
                "-k",
                "--since",
                "-1 hour",
                "--no-pager",
                "-n",
                str(min(max(limit * 3, 200), 1000)),
            ]
        )
        if not result.ok:
            return []
        return [
            line[:1000]
            for line in result.stdout.splitlines()
            if "[UFW " in line
        ][-limit:]


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
                action = (
                    "deny"
                    if str(rich_rule).rstrip().endswith(" drop")
                    else "reject"
                    if str(rich_rule).rstrip().endswith(" reject")
                    else "allow"
                )
                rules.append(
                    FirewallRule(
                        backend=self.backend,
                        action=action,
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
            dbus.change_rich_rule(
                zone,
                str(rule.metadata["rich_rule"]),
                method,
                permanent,
                rule.temporary_seconds,
            )
        elif rule.source or rule.destination or rule.action != RuleAction.ALLOW:
            dbus.change_rich_rule(
                zone,
                self._rich_rule(rule),
                method,
                permanent,
                rule.temporary_seconds,
            )
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

    @staticmethod
    def _rich_rule(rule: FirewallRule) -> str:
        parts = ["rule"]
        networks = [
            ipaddress.ip_network(value)
            for value in (rule.source, rule.destination)
            if value
        ]
        if networks:
            parts.append(f'family="ipv{networks[0].version}"')
        if rule.source:
            parts.append(f'source address="{rule.source}"')
        if rule.destination:
            parts.append(f'destination address="{rule.destination}"')
        if rule.port:
            parts.append(f'port port="{rule.port}" protocol="{rule.protocol}"')
        elif rule.service:
            parts.append(f'service name="{rule.service}"')
        action = {
            RuleAction.ALLOW: "accept",
            RuleAction.DENY: "drop",
            RuleAction.REJECT: "reject",
        }.get(rule.action)
        if action is None:
            raise FirewallError("firewalld 不支持该规则动作")
        parts.append(action)
        return " ".join(parts)

    def service_action(self, action: ServiceAction) -> None:
        _systemd_action(self.runner, "firewalld.service", action)

    def rejection_logs(self, limit: int = 200) -> list[str]:
        if not self.runner.exists("journalctl"):
            return []
        result = self.runner.run(
            [
                "journalctl",
                "-k",
                "--since",
                "-1 hour",
                "--no-pager",
                "-n",
                str(min(max(limit * 3, 200), 1000)),
            ]
        )
        if not result.ok:
            return []
        markers = ("REJECT", "DROP", "firewalld")
        return [
            line[:1000]
            for line in result.stdout.splitlines()
            if any(marker in line for marker in markers)
        ][-limit:]

    @staticmethod
    def _validate_object_ref(object_type: str, name: str) -> None:
        if object_type not in {"zone", "policy", "service", "ipset"}:
            raise FirewallError("不支持的 firewalld 对象类型")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name):
            raise FirewallError("firewalld 对象名称无效")

    @staticmethod
    def _custom_path(object_type: str, name: str) -> pathlib.Path:
        directories = {
            "zone": "zones",
            "policy": "policies",
            "service": "services",
            "ipset": "ipsets",
        }
        return pathlib.Path("/etc/firewalld") / directories[object_type] / f"{name}.xml"

    def _cmd(self, argv: list[str]) -> str:
        result = self.runner.run(argv, timeout=30)
        if not result.ok:
            raise FirewallError(
                result.stderr.strip() or result.stdout.strip() or "firewall-cmd 操作失败"
            )
        return result.stdout

    def list_objects(self) -> list[dict[str, Any]]:
        queries = {
            "zone": "--get-zones",
            "policy": "--get-policies",
            "service": "--get-services",
            "ipset": "--get-ipsets",
        }
        output: list[dict[str, Any]] = []
        for object_type, option in queries.items():
            result = self.runner.run(["firewall-cmd", "--permanent", option])
            if not result.ok:
                continue
            names = result.stdout.split()
            for name in names:
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name):
                    continue
                output.append(
                    {
                        "backend": self.backend.value,
                        "object_type": object_type,
                        "name": name,
                        "builtin": not self._custom_path(object_type, name).exists(),
                    }
                )
        return output

    def get_object(self, object_type: str, name: str) -> FirewallObject:
        self._validate_object_ref(object_type, name)
        selectors = {
            "zone": f"--zone={name}",
            "policy": f"--policy={name}",
            "service": f"--info-service={name}",
            "ipset": f"--info-ipset={name}",
        }
        argv = ["firewall-cmd", "--permanent", selectors[object_type]]
        if object_type in {"zone", "policy"}:
            argv.append("--list-all")
        raw = self._cmd(argv)
        settings = self._parse_object_info(object_type, raw)
        return FirewallObject(
            backend=self.backend,
            object_type=object_type,
            name=name,
            builtin=not self._custom_path(object_type, name).exists(),
            settings=settings,
        )

    @staticmethod
    def _parse_object_info(object_type: str, text: str) -> dict[str, Any]:
        values: dict[str, str | list[str]] = {}
        current_key = ""
        for raw in text.splitlines():
            if not raw.strip():
                continue
            stripped = raw.strip()
            if (
                raw[:1].isspace()
                and current_key == "rich rules"
                and stripped.startswith("rule ")
            ):
                rich = values.setdefault(current_key, [])
                if isinstance(rich, list):
                    rich.append(stripped)
                continue
            if (
                raw[:1].isspace()
                and current_key == "forward-ports"
                and stripped.startswith("port=")
            ):
                forwards = values.get(current_key)
                if not isinstance(forwards, list):
                    forwards = [str(forwards)] if forwards else []
                    values[current_key] = forwards
                forwards.append(stripped)
                continue
            line = stripped
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            current_key = key.strip().lower()
            values[current_key] = value.strip()

        def names(key: str) -> list[str]:
            value = values.get(key, "")
            return str(value).split() if not isinstance(value, list) else value

        def ports(key: str) -> list[dict[str, str]]:
            output: list[dict[str, str]] = []
            for value in names(key):
                if "/" not in value:
                    continue
                port, protocol = value.rsplit("/", 1)
                output.append({"port": port.replace(":", "-"), "protocol": protocol})
            return output

        def forward_ports() -> list[dict[str, str]]:
            output: list[dict[str, str]] = []
            value = values.get("forward-ports", "")
            entries = value if isinstance(value, list) else [str(value)]
            for entry in entries:
                fields = dict(
                    part.split("=", 1)
                    for part in re.split(r"[:,]\s*", entry)
                    if "=" in part
                )
                if fields.get("port") and fields.get("proto"):
                    output.append(
                        {
                            "port": fields["port"],
                            "protocol": fields["proto"],
                            "to_port": fields.get("toport", ""),
                            "to_address": fields.get("toaddr", ""),
                        }
                    )
            return output

        if object_type == "zone":
            return {
                "target": str(values.get("target", "default")).upper(),
                "services": names("services"),
                "ports": ports("ports"),
                "source_ports": ports("source-ports"),
                "protocols": names("protocols"),
                "sources": names("sources"),
                "interfaces": names("interfaces"),
                "icmp_blocks": names("icmp-blocks"),
                "icmp_block_inversion": str(
                    values.get("icmp-block-inversion", "no")
                ).lower()
                == "yes",
                "rich_rules": names("rich rules"),
                "masquerade": str(values.get("masquerade", "no")).lower() == "yes",
                "forward": str(values.get("forward", "no")).lower() == "yes",
                "forward_ports": forward_ports(),
                "ingress_priority": int(str(values.get("ingress-priority", "0")) or 0),
                "egress_priority": int(str(values.get("egress-priority", "0")) or 0),
            }
        if object_type == "policy":
            return {
                "target": str(values.get("target", "CONTINUE")).upper(),
                "priority": int(str(values.get("priority", "-1")) or -1),
                "ingress_zones": names("ingress-zones"),
                "egress_zones": names("egress-zones"),
                "services": names("services"),
                "ports": ports("ports"),
                "source_ports": ports("source-ports"),
                "protocols": names("protocols"),
                "icmp_blocks": names("icmp-blocks"),
                "icmp_block_inversion": str(
                    values.get("icmp-block-inversion", "no")
                ).lower()
                == "yes",
                "rich_rules": names("rich rules"),
                "masquerade": str(values.get("masquerade", "no")).lower() == "yes",
                "forward_ports": forward_ports(),
                "disabled": str(
                    values.get("disable", values.get("disabled", "no"))
                ).lower()
                == "yes",
            }
        if object_type == "service":
            destinations: dict[str, str] = {}
            for value in names("destination"):
                if ":" in value:
                    family, address = value.split(":", 1)
                    destinations[family] = address
            return {
                "short": str(values.get("short", "")),
                "description": str(values.get("description", "")),
                "ports": ports("ports"),
                "source_ports": ports("source-ports"),
                "protocols": names("protocols"),
                "modules": names("modules"),
                "destinations": destinations,
            }
        options: dict[str, str] = {}
        for option in names("options"):
            if "=" in option:
                key, value = option.split("=", 1)
                options[key] = value
        return {
            "short": str(values.get("short", "")),
            "description": str(values.get("description", "")),
            "type": str(values.get("type", "hash:ip")),
            "family": options.get("family", "inet"),
            "hashsize": int(options.get("hashsize", "1024")),
            "maxelem": int(options.get("maxelem", "65536")),
            "timeout": int(options.get("timeout", "0")),
            "entries": names("entries"),
        }

    def apply_object(
        self,
        operation: str,
        item: FirewallObject,
        *,
        before: FirewallObject | None = None,
    ) -> None:
        if item.backend != self.backend:
            raise FirewallError("高级对象后端不匹配")
        if operation not in {"add", "delete", "restore", "update"}:
            raise FirewallError("不支持的高级对象操作")
        if item.builtin and operation in {"delete", "update"}:
            raise FirewallError("内置对象不能删除或覆盖")
        if operation in {"add", "restore"}:
            self._create_object(item)
        elif operation == "delete":
            self._delete_object(item)
        else:
            if before is None:
                raise FirewallError("更新对象需要原始快照")
            if before.builtin:
                raise FirewallError("内置对象不能覆盖")
            try:
                self._delete_object(before, reload_after=False)
                self._create_object(item, reload_after=False)
                self._reload_firewalld()
            except Exception:
                try:
                    self._delete_object(item, reload_after=False, ignore_missing=True)
                    self._create_object(before, reload_after=False)
                    self._reload_firewalld()
                except Exception:
                    pass
                raise

    def _delete_object(
        self,
        item: FirewallObject,
        *,
        reload_after: bool = True,
        ignore_missing: bool = False,
    ) -> None:
        options = {
            "zone": "--delete-zone",
            "policy": "--delete-policy",
            "service": "--delete-service",
            "ipset": "--delete-ipset",
        }
        argv = ["firewall-cmd", "--permanent", f"{options[item.object_type]}={item.name}"]
        result = self.runner.run(argv, timeout=30)
        if not result.ok and not ignore_missing:
            raise FirewallError(result.stderr.strip() or "删除 firewalld 对象失败")
        if reload_after:
            self._reload_firewalld()

    def _create_object(
        self, item: FirewallObject, *, reload_after: bool = True
    ) -> None:
        create_options = {
            "zone": "--new-zone",
            "policy": "--new-policy",
            "service": "--new-service",
            "ipset": "--new-ipset",
        }
        argv = [
            "firewall-cmd",
            "--permanent",
            f"{create_options[item.object_type]}={item.name}",
        ]
        if item.object_type == "ipset":
            settings = item.settings
            argv.extend(
                [
                    f"--type={settings['type']}",
                    f"--family={settings['family']}",
                    f"--option=hashsize={settings['hashsize']}",
                    f"--option=maxelem={settings['maxelem']}",
                ]
            )
            if settings["timeout"]:
                argv.append(f"--option=timeout={settings['timeout']}")
        self._cmd(argv)
        try:
            self._populate_object(item)
        except Exception:
            self._delete_object(item, reload_after=False, ignore_missing=True)
            raise
        if reload_after:
            self._reload_firewalld()

    def _populate_object(self, item: FirewallObject) -> None:
        settings = item.settings
        if item.object_type == "zone":
            base = ["firewall-cmd", "--permanent", f"--zone={item.name}"]
            if settings["target"] != "DEFAULT":
                self._cmd(base + [f"--set-target={settings['target']}"])
            if settings["ingress_priority"]:
                self._cmd(
                    base
                    + [f"--set-ingress-priority={settings['ingress_priority']}"]
                )
            if settings["egress_priority"]:
                self._cmd(
                    base
                    + [f"--set-egress-priority={settings['egress_priority']}"]
                )
            self._populate_rule_elements(base, settings)
            for value in settings["sources"]:
                self._cmd(base + [f"--add-source={value}"])
            for value in settings["interfaces"]:
                self._cmd(base + [f"--add-interface={value}"])
            for value in settings["protocols"]:
                self._cmd(base + [f"--add-protocol={value}"])
            for value in settings["source_ports"]:
                self._cmd(
                    base
                    + [f"--add-source-port={value['port']}/{value['protocol']}"]
                )
            for value in settings["icmp_blocks"]:
                self._cmd(base + [f"--add-icmp-block={value}"])
            if settings["icmp_block_inversion"]:
                self._cmd(base + ["--add-icmp-block-inversion"])
            if settings["forward"]:
                self._cmd(base + ["--add-forward"])
            return
        if item.object_type == "policy":
            base = ["firewall-cmd", "--permanent", f"--policy={item.name}"]
            self._cmd(base + [f"--set-target={settings['target']}"])
            self._cmd(base + [f"--set-priority={settings['priority']}"])
            for value in settings["ingress_zones"]:
                self._cmd(base + [f"--add-ingress-zone={value}"])
            for value in settings["egress_zones"]:
                self._cmd(base + [f"--add-egress-zone={value}"])
            if settings["disabled"]:
                self._cmd(base + ["--add-disable"])
            self._populate_rule_elements(base, settings)
            for value in settings["protocols"]:
                self._cmd(base + [f"--add-protocol={value}"])
            for value in settings["source_ports"]:
                self._cmd(
                    base
                    + [f"--add-source-port={value['port']}/{value['protocol']}"]
                )
            for value in settings["icmp_blocks"]:
                self._cmd(base + [f"--add-icmp-block={value}"])
            if settings["icmp_block_inversion"]:
                self._cmd(base + ["--add-icmp-block-inversion"])
            return
        if item.object_type == "service":
            base = ["firewall-cmd", "--permanent", f"--service={item.name}"]
            if settings["short"]:
                self._cmd(base + [f"--set-short={settings['short']}"])
            if settings["description"]:
                self._cmd(base + [f"--set-description={settings['description']}"])
            for value in settings["ports"]:
                self._cmd(base + [f"--add-port={value['port']}/{value['protocol']}"])
            for value in settings["source_ports"]:
                self._cmd(
                    base
                    + [f"--add-source-port={value['port']}/{value['protocol']}"]
                )
            for value in settings["protocols"]:
                self._cmd(base + [f"--add-protocol={value}"])
            for value in settings["modules"]:
                self._cmd(base + [f"--add-module={value}"])
            for family, destination in settings["destinations"].items():
                self._cmd(base + [f"--set-destination={family}:{destination}"])
            return
        base = ["firewall-cmd", "--permanent", f"--ipset={item.name}"]
        if settings["short"]:
            self._cmd(base + [f"--set-short={settings['short']}"])
        if settings["description"]:
            self._cmd(base + [f"--set-description={settings['description']}"])
        for value in settings["entries"]:
            self._cmd(base + [f"--add-entry={value}"])

    def _populate_rule_elements(
        self, base: list[str], settings: dict[str, Any]
    ) -> None:
        for value in settings.get("services", []):
            self._cmd(base + [f"--add-service={value}"])
        for value in settings.get("ports", []):
            self._cmd(base + [f"--add-port={value['port']}/{value['protocol']}"])
        for value in settings.get("rich_rules", []):
            self._cmd(base + [f"--add-rich-rule={value}"])
        if settings.get("masquerade"):
            self._cmd(base + ["--add-masquerade"])
        for value in settings.get("forward_ports", []):
            spec = (
                f"port={value['port']}:proto={value['protocol']}:"
                f"toport={value['to_port']}:toaddr={value['to_address']}"
            )
            self._cmd(base + [f"--add-forward-port={spec}"])

    def _reload_firewalld(self) -> None:
        try:
            self._ensure_dbus().reload()
        except Exception:
            self._cmd(["firewall-cmd", "--reload"])


class ReadOnlyAdapter(FirewallAdapter):
    def __init__(self, runner: CommandRunner, backend: BackendName) -> None:
        super().__init__(runner)
        self.backend = backend
        candidates = {
            BackendName.NFTABLES: ("nftables.service",),
            BackendName.IPTABLES: (
                "iptables.service",
                "ip6tables.service",
                "netfilter-persistent.service",
            ),
        }.get(backend, ())
        self.service_unit = _detect_service_unit(runner, candidates)

    def status(self) -> FirewallStatus:
        unit = self.service_unit
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
        unit = self.service_unit
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


class NonSystemdAdapter(FirewallAdapter):
    def __init__(self, delegate: FirewallAdapter) -> None:
        super().__init__(delegate.runner)
        self.delegate = delegate
        self.backend = delegate.backend

    def status(self) -> FirewallStatus:
        status = self.delegate.status()
        status.capabilities.writable = False
        status.capabilities.service_actions = []
        status.capabilities.reason = "未检测到 systemd，WallPilot 已切换为只读模式"
        status.message = status.capabilities.reason
        return status

    def list_rules(self) -> list[FirewallRule]:
        return self.delegate.list_rules()

    def list_objects(self) -> list[dict[str, Any]]:
        return self.delegate.list_objects()

    def get_object(self, object_type: str, name: str) -> FirewallObject:
        return self.delegate.get_object(object_type, name)

    def rejection_logs(self, limit: int = 200) -> list[str]:
        return self.delegate.rejection_logs(limit)


def adapter_for(
    detection: Detection, runner: CommandRunner, *, systemd: bool = True
) -> FirewallAdapter:
    if detection.conflict:
        return ConflictAdapter(runner, detection.active_backends)
    if detection.backend == BackendName.FIREWALLD:
        adapter: FirewallAdapter = FirewalldAdapter(runner)
    elif detection.backend == BackendName.UFW:
        adapter = UfwAdapter(runner)
    else:
        adapter = ReadOnlyAdapter(runner, detection.backend)
    return adapter if systemd else NonSystemdAdapter(adapter)


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


def _detect_service_unit(
    runner: CommandRunner, candidates: tuple[str, ...]
) -> str:
    if not runner.exists("systemctl"):
        return ""
    for unit in candidates:
        result = runner.run(
            ["systemctl", "show", unit, "--property=LoadState", "--value"],
            allowed_returncodes=(0, 1, 3, 4),
        )
        if result.stdout.strip() == "loaded":
            return unit
    return ""


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
