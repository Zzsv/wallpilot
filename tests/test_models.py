from __future__ import annotations

import pytest
from pydantic import ValidationError

from wallpilot.models import BackendName, FirewallObject, FirewallRule


def test_rule_normalizes_port_and_network_and_gets_stable_id() -> None:
    rule = FirewallRule(
        backend=BackendName.UFW,
        port="8000:8100",
        protocol="tcp",
        source="192.168.1.24/24",
        comment="internal app",
    )
    assert rule.port == "8000-8100"
    assert rule.source == "192.168.1.0/24"
    assert len(rule.id) == 20
    clone = FirewallRule.model_validate(rule.model_dump(exclude={"id"}))
    assert clone.id == rule.id


@pytest.mark.parametrize(
    "payload",
    [
        {"port": "0", "protocol": "tcp"},
        {"port": "65536", "protocol": "tcp"},
        {"port": "9000-8000", "protocol": "tcp"},
        {"port": "22;reboot", "protocol": "tcp"},
        {"port": "22", "protocol": "any"},
        {"port": "22", "protocol": "tcp", "source": "not-an-ip"},
        {"port": "22", "protocol": "tcp", "zone": "../../etc"},
    ],
)
def test_rule_rejects_unsafe_values(payload: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        FirewallRule(backend=BackendName.UFW, **payload)


def test_rule_requires_a_port_service_or_rich_rule() -> None:
    with pytest.raises(ValidationError):
        FirewallRule(backend=BackendName.UFW)


def test_firewalld_object_normalizes_settings_and_gets_stable_id() -> None:
    item = FirewallObject(
        object_type="zone",
        name="trusted-office",
        settings={
            "target": "accept",
            "ports": [{"port": "8000:8100", "protocol": "tcp"}],
            "sources": ["192.168.1.24/24"],
            "services": ["https", "ssh", "ssh"],
        },
    )
    assert item.settings["target"] == "ACCEPT"
    assert item.settings["ports"] == [{"port": "8000-8100", "protocol": "tcp"}]
    assert item.settings["sources"] == ["192.168.1.0/24"]
    assert item.settings["services"] == ["https", "ssh"]
    clone = FirewallObject.model_validate(item.model_dump(exclude={"id"}))
    assert clone.id == item.id


@pytest.mark.parametrize(
    "payload",
    [
        {"object_type": "zone", "name": "../public", "settings": {}},
        {"object_type": "zone", "name": "public", "settings": {"unknown": True}},
        {
            "object_type": "service",
            "name": "web",
            "settings": {"ports": [{"port": "443;reboot", "protocol": "tcp"}]},
        },
        {
            "object_type": "ipset",
            "name": "blocked",
            "settings": {"entries": ["192.0.2.1;reboot"]},
        },
        {
            "object_type": "ipset",
            "name": "blocked",
            "settings": {"type": "bitmap:ip"},
        },
    ],
)
def test_firewalld_object_rejects_unsafe_or_unknown_values(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        FirewallObject.model_validate(payload)
