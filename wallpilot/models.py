from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .compat import UTC, StrEnum


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BackendName(StrEnum):
    FIREWALLD = "firewalld"
    UFW = "ufw"
    NFTABLES = "nftables"
    IPTABLES = "iptables"
    NONE = "none"
    CONFLICT = "conflict"


class ServiceAction(StrEnum):
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    RELOAD = "reload"
    ENABLE = "enable"
    DISABLE = "disable"


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    LIMIT = "limit"


class FirewallRule(StrictModel):
    id: str = ""
    backend: BackendName
    action: RuleAction = RuleAction.ALLOW
    direction: Literal["in", "out", "route"] = "in"
    protocol: Literal["tcp", "udp", "sctp", "dccp", "any"] = "tcp"
    port: str | None = None
    source: str | None = None
    destination: str | None = None
    interface_in: str | None = None
    interface_out: str | None = None
    service: str | None = None
    zone: str | None = None
    comment: str = ""
    temporary_seconds: int = Field(default=0, ge=0, le=604800)
    family: Literal["ipv4", "ipv6", "any"] = "any"
    log: Literal["off", "log", "log-all"] = "off"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if not re.fullmatch(r"\d{1,5}(?::\d{1,5}|-\d{1,5})?", value):
            raise ValueError("端口必须是单个端口或端口范围")
        normalized = value.replace(":", "-")
        parts = [int(item) for item in normalized.split("-")]
        if any(part < 1 or part > 65535 for part in parts):
            raise ValueError("端口必须在 1 到 65535 之间")
        if len(parts) == 2 and parts[0] > parts[1]:
            raise ValueError("端口范围起始值不能大于结束值")
        return normalized

    @field_validator("source", "destination")
    @classmethod
    def validate_network(cls, value: str | None) -> str | None:
        if not value or value.lower() in {"any", "anywhere"}:
            return None
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError("来源或目标必须是有效的 IPv4/IPv6 地址或 CIDR") from exc

    @field_validator("interface_in", "interface_out", "zone", "service")
    @classmethod
    def validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,64}", value):
            raise ValueError("名称包含不允许的字符")
        return value

    @field_validator("comment")
    @classmethod
    def validate_comment(cls, value: str) -> str:
        clean = value.strip()
        if len(clean) > 160 or any(ord(ch) < 32 for ch in clean):
            raise ValueError("备注长度或字符不合法")
        return clean

    @model_validator(mode="after")
    def require_target(self) -> "FirewallRule":
        supported_elements = {
            "rich_rule",
            "source_binding",
            "protocol_binding",
            "source_port",
            "icmp_block",
            "masquerade",
            "forward_port",
        }
        if (
            not self.port
            and not self.service
            and not supported_elements.intersection(self.metadata)
        ):
            raise ValueError("规则必须包含端口、服务或富规则")
        if self.protocol == "any" and self.port:
            raise ValueError("指定端口时必须明确协议")
        if self.log != "off" and self.backend != BackendName.UFW:
            raise ValueError("逐规则日志选项仅适用于 UFW")
        networks = [
            ipaddress.ip_network(value)
            for value in (self.source, self.destination)
            if value
        ]
        if len({network.version for network in networks}) > 1:
            raise ValueError("来源与目标地址必须使用相同的 IP 地址族")
        if self.family != "any":
            expected_version = 4 if self.family == "ipv4" else 6
            if not networks or any(
                network.version != expected_version for network in networks
            ):
                raise ValueError("指定地址族时，来源或目标必须包含同一地址族的地址")
        if self.backend == BackendName.FIREWALLD:
            if self.direction != "in":
                raise ValueError("firewalld 出站和路由规则请使用策略对象")
            if self.interface_in or self.interface_out:
                raise ValueError("firewalld 网卡绑定请在区域对象中配置")
            if self.action == RuleAction.LIMIT:
                raise ValueError("firewalld 限速请使用经过审核的富规则")
        if not self.id:
            self.id = self.fingerprint()
        return self

    def fingerprint(self) -> str:
        data = self.model_dump(exclude={"id"}, mode="json")
        if self.backend == BackendName.UFW:
            metadata = dict(data.get("metadata") or {})
            metadata.pop("ufw_number", None)
            metadata.pop("raw", None)
            data["metadata"] = metadata
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


class FirewallCapabilities(BaseModel):
    backend: BackendName
    writable: bool
    service_actions: list[ServiceAction] = Field(default_factory=list)
    features: list[str] = Field(default_factory=list)
    reason: str = ""


class FirewallStatus(BaseModel):
    backend: BackendName
    active: bool = False
    enabled: bool | None = None
    version: str = ""
    service_unit: str = ""
    default_policy: str = "unknown"
    active_zones: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    capabilities: FirewallCapabilities
    message: str = ""


class SystemProfile(BaseModel):
    hostname: str
    os_id: str
    os_like: list[str] = Field(default_factory=list)
    os_name: str
    os_version: str
    kernel: str
    architecture: str
    systemd: bool
    timezone: str


class SystemMetrics(BaseModel):
    collected_at: datetime
    uptime_seconds: float = 0
    load_1: float = 0
    load_5: float = 0
    load_15: float = 0
    cpu_count: int = 0
    memory_total: int = 0
    memory_available: int = 0
    swap_total: int = 0
    swap_free: int = 0
    disks: list[dict[str, Any]] = Field(default_factory=list)
    network: list[dict[str, Any]] = Field(default_factory=list)


class ServerStatus(BaseModel):
    profile: SystemProfile
    metrics: SystemMetrics
    firewall: FirewallStatus
    failed_services: list[str] = Field(default_factory=list)
    security_services: dict[str, str] = Field(default_factory=dict)
    security_modules: dict[str, str] = Field(default_factory=dict)
    security_updates: dict[str, str] = Field(default_factory=dict)
    listeners: list[dict[str, Any]] = Field(default_factory=list)
    connections: list[dict[str, Any]] = Field(default_factory=list)
    network_interfaces: list[dict[str, Any]] = Field(default_factory=list)
    default_routes: list[dict[str, Any]] = Field(default_factory=list)
    dns_servers: list[str] = Field(default_factory=list)
    ssh_sessions: list[dict[str, Any]] = Field(default_factory=list)
    containers: list[dict[str, Any]] = Field(default_factory=list)
    reboot_required: bool = False
    alerts: list[dict[str, str]] = Field(default_factory=list)


class DraftCreate(StrictModel):
    operation: Literal["add", "delete", "restore", "update"]
    object_type: Literal["rule", "policy", "zone", "service", "ipset"] = "rule"
    payload: dict[str, Any]
    reason: str = Field(default="", max_length=240)


class DraftConfirmation(StrictModel):
    code: str = Field(min_length=6, max_length=6)
    totp: str | None = Field(default=None, min_length=6, max_length=8)
    hostname: str | None = Field(default=None, max_length=255)


class ServiceActionRequest(StrictModel):
    action: ServiceAction
    totp: str | None = None
    hostname: str | None = None


class PurgeRequest(StrictModel):
    password: str = Field(min_length=1, max_length=512)
    totp: str = Field(min_length=6, max_length=8)
    confirmation: str


class PortSpec(StrictModel):
    port: str
    protocol: Literal["tcp", "udp", "sctp", "dccp"] = "tcp"

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: str) -> str:
        normalized = value.replace(":", "-")
        if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", normalized):
            raise ValueError("端口格式无效")
        parts = [int(item) for item in normalized.split("-")]
        if any(item < 1 or item > 65535 for item in parts):
            raise ValueError("端口必须在 1 到 65535 之间")
        if len(parts) == 2 and parts[0] > parts[1]:
            raise ValueError("端口范围顺序错误")
        return normalized


class ForwardPortSpec(StrictModel):
    port: str
    protocol: Literal["tcp", "udp", "sctp", "dccp"] = "tcp"
    to_port: str = ""
    to_address: str = ""

    @field_validator("port", "to_port")
    @classmethod
    def validate_port(cls, value: str) -> str:
        if not value:
            return ""
        return PortSpec(port=value).port

    @field_validator("to_address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        if not value:
            return ""
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("转发目标地址无效") from exc

    @model_validator(mode="after")
    def require_destination(self) -> "ForwardPortSpec":
        if not self.to_port and not self.to_address:
            raise ValueError("端口转发必须指定目标端口或目标地址")
        return self


class FirewallObject(StrictModel):
    backend: Literal[BackendName.FIREWALLD] = BackendName.FIREWALLD
    object_type: Literal["zone", "policy", "service", "ipset"]
    name: str
    builtin: bool = False
    settings: dict[str, Any] = Field(default_factory=dict)
    id: str = ""

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value):
            raise ValueError("对象名称必须以字母开头，且只包含字母、数字、横线或下划线")
        return value

    @model_validator(mode="after")
    def validate_settings(self) -> "FirewallObject":
        validators = {
            "zone": self._validate_zone,
            "policy": self._validate_policy,
            "service": self._validate_service,
            "ipset": self._validate_ipset,
        }
        self.settings = validators[self.object_type](dict(self.settings))
        if not self.id:
            raw = json.dumps(
                self.model_dump(exclude={"id"}, mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            self.id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]
        return self

    @staticmethod
    def _names(values: Any, field: str) -> list[str]:
        output: list[str] = []
        for value in values or []:
            text = str(value)
            if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,64}", text):
                raise ValueError(f"{field} 包含无效名称")
            output.append(text)
        return sorted(set(output))

    @staticmethod
    def _networks(values: Any) -> list[str]:
        output: list[str] = []
        for value in values or []:
            try:
                output.append(str(ipaddress.ip_network(str(value), strict=False)))
            except ValueError as exc:
                raise ValueError("来源地址必须是有效的 IPv4/IPv6 或 CIDR") from exc
        return sorted(set(output))

    @staticmethod
    def _rich_rules(values: Any) -> list[str]:
        output: list[str] = []
        for value in values or []:
            text = str(value).strip()
            if (
                not text.startswith("rule ")
                or len(text) > 2048
                or any(ord(ch) < 32 for ch in text)
            ):
                raise ValueError("富规则必须使用 firewalld rich language 的 rule 开头格式")
            output.append(text)
        return output

    @staticmethod
    def _ports(values: Any) -> list[dict[str, str]]:
        return [
            PortSpec.model_validate(value).model_dump(mode="json")
            for value in values or []
        ]

    @staticmethod
    def _forwards(values: Any) -> list[dict[str, str]]:
        return [
            ForwardPortSpec.model_validate(value).model_dump(mode="json")
            for value in values or []
        ]

    def _validate_zone(self, settings: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "target",
            "services",
            "ports",
            "source_ports",
            "protocols",
            "sources",
            "interfaces",
            "icmp_blocks",
            "icmp_block_inversion",
            "rich_rules",
            "masquerade",
            "forward",
            "forward_ports",
            "ingress_priority",
            "egress_priority",
        }
        self._reject_unknown(settings, allowed)
        target = str(settings.get("target", "default")).upper()
        if target not in {"DEFAULT", "ACCEPT", "DROP", "REJECT"}:
            raise ValueError("区域目标无效")
        return {
            "target": target,
            "services": self._names(settings.get("services"), "服务"),
            "ports": self._ports(settings.get("ports")),
            "source_ports": self._ports(settings.get("source_ports")),
            "protocols": self._names(settings.get("protocols"), "协议"),
            "sources": self._networks(settings.get("sources")),
            "interfaces": self._names(settings.get("interfaces"), "网卡"),
            "icmp_blocks": self._names(settings.get("icmp_blocks"), "ICMP类型"),
            "icmp_block_inversion": bool(
                settings.get("icmp_block_inversion", False)
            ),
            "rich_rules": self._rich_rules(settings.get("rich_rules")),
            "masquerade": bool(settings.get("masquerade", False)),
            "forward": bool(settings.get("forward", False)),
            "forward_ports": self._forwards(settings.get("forward_ports")),
            "ingress_priority": self._priority(settings.get("ingress_priority", 0)),
            "egress_priority": self._priority(settings.get("egress_priority", 0)),
        }

    def _validate_policy(self, settings: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "target",
            "priority",
            "ingress_zones",
            "egress_zones",
            "services",
            "ports",
            "source_ports",
            "protocols",
            "icmp_blocks",
            "icmp_block_inversion",
            "rich_rules",
            "masquerade",
            "forward_ports",
            "disabled",
        }
        self._reject_unknown(settings, allowed)
        target = str(settings.get("target", "CONTINUE")).upper()
        if target not in {"ACCEPT", "DROP", "REJECT", "CONTINUE"}:
            raise ValueError("策略目标无效")
        return {
            "target": target,
            "priority": self._priority(settings.get("priority", -1)),
            "ingress_zones": self._names(settings.get("ingress_zones"), "入口区域"),
            "egress_zones": self._names(settings.get("egress_zones"), "出口区域"),
            "services": self._names(settings.get("services"), "服务"),
            "ports": self._ports(settings.get("ports")),
            "source_ports": self._ports(settings.get("source_ports")),
            "protocols": self._names(settings.get("protocols"), "协议"),
            "icmp_blocks": self._names(settings.get("icmp_blocks"), "ICMP类型"),
            "icmp_block_inversion": bool(
                settings.get("icmp_block_inversion", False)
            ),
            "rich_rules": self._rich_rules(settings.get("rich_rules")),
            "masquerade": bool(settings.get("masquerade", False)),
            "forward_ports": self._forwards(settings.get("forward_ports")),
            "disabled": bool(settings.get("disabled", False)),
        }

    def _validate_service(self, settings: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "short",
            "description",
            "ports",
            "source_ports",
            "protocols",
            "modules",
            "destinations",
        }
        self._reject_unknown(settings, allowed)
        destinations: dict[str, str] = {}
        for family, value in dict(settings.get("destinations") or {}).items():
            if family not in {"ipv4", "ipv6"}:
                raise ValueError("服务目标地址族只能是 ipv4 或 ipv6")
            destinations[family] = str(ipaddress.ip_network(str(value), strict=False))
        short = str(settings.get("short", "")).strip()
        description = str(settings.get("description", "")).strip()
        if len(short) > 80 or len(description) > 300:
            raise ValueError("服务名称或说明过长")
        return {
            "short": short,
            "description": description,
            "ports": self._ports(settings.get("ports")),
            "source_ports": self._ports(settings.get("source_ports")),
            "protocols": self._names(settings.get("protocols"), "协议"),
            "modules": self._names(settings.get("modules"), "模块"),
            "destinations": destinations,
        }

    def _validate_ipset(self, settings: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "short",
            "description",
            "type",
            "family",
            "hashsize",
            "maxelem",
            "timeout",
            "entries",
        }
        self._reject_unknown(settings, allowed)
        ipset_type = str(settings.get("type", "hash:ip"))
        if ipset_type not in {
            "hash:ip",
            "hash:net",
            "hash:mac",
            "hash:ip,port",
            "hash:net,port",
        }:
            raise ValueError("暂不支持该 IPSet 类型")
        family = str(settings.get("family", "inet"))
        if family not in {"inet", "inet6"}:
            raise ValueError("IPSet 地址族只能是 inet 或 inet6")
        entries: list[str] = []
        for raw in settings.get("entries") or []:
            value = str(raw).strip()
            if not value or len(value) > 160 or re.search(r"[\s;'\"`$]", value):
                raise ValueError("IPSet 条目包含无效字符")
            entries.append(value)
        short = str(settings.get("short", "")).strip()
        description = str(settings.get("description", "")).strip()
        if len(short) > 80 or len(description) > 300:
            raise ValueError("IPSet 名称或说明过长")
        return {
            "short": short,
            "description": description,
            "type": ipset_type,
            "family": family,
            "hashsize": self._positive_int(settings.get("hashsize", 1024), 64, 1_048_576),
            "maxelem": self._positive_int(settings.get("maxelem", 65536), 1, 10_000_000),
            "timeout": self._positive_int(settings.get("timeout", 0), 0, 31_536_000),
            "entries": sorted(set(entries)),
        }

    @staticmethod
    def _priority(value: Any) -> int:
        number = int(value)
        if number < -32768 or number > 32767:
            raise ValueError("优先级必须在 -32768 到 32767 之间")
        return number

    @staticmethod
    def _positive_int(value: Any, minimum: int, maximum: int) -> int:
        number = int(value)
        if number < minimum or number > maximum:
            raise ValueError("数值超出允许范围")
        return number

    @staticmethod
    def _reject_unknown(settings: dict[str, Any], allowed: set[str]) -> None:
        unknown = set(settings) - allowed
        if unknown:
            raise ValueError(f"不支持的配置字段：{', '.join(sorted(unknown))}")


def utc_now() -> datetime:
    return datetime.now(UTC)
