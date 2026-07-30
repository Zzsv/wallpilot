from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
        if not self.id:
            self.id = self.fingerprint()
        return self

    def fingerprint(self) -> str:
        data = self.model_dump(exclude={"id"}, mode="json")
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
    listeners: list[dict[str, Any]] = Field(default_factory=list)
    containers: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, str]] = Field(default_factory=list)


class DraftCreate(StrictModel):
    operation: Literal["add", "delete", "restore"]
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


def utc_now() -> datetime:
    return datetime.now(UTC)
