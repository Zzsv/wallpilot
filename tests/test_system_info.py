from __future__ import annotations

from pathlib import Path

from wallpilot.runner import CommandResult, FakeRunner
from wallpilot.system_info import (
    collect_default_routes,
    collect_dns_servers,
    collect_network_interfaces,
    collect_profile,
    parse_loadavg,
    parse_meminfo,
    parse_net_dev,
    parse_os_release,
)


def test_parse_os_release_handles_quotes_and_id_like() -> None:
    release = parse_os_release(
        """
        NAME="Rocky Linux"
        PRETTY_NAME="Rocky Linux 9.5 (Blue Onyx)"
        ID=rocky
        ID_LIKE="rhel centos fedora"
        VERSION_ID="9.5"
        """
    )
    profile = collect_profile(release)
    assert profile.os_id == "rocky"
    assert profile.os_like == ["rhel", "centos", "fedora"]
    assert profile.os_version == "9.5"


def test_proc_parsers_are_defensive() -> None:
    mem = parse_meminfo("MemTotal: 1024 kB\nMemAvailable: 512 kB\nbroken")
    assert mem["MemTotal"] == 1024 * 1024
    assert parse_loadavg("0.20 0.30 0.40 1/5 1") == (0.2, 0.3, 0.4)
    rows = parse_net_dev(
        "Inter-| Receive\n eth0: 100 1 2 3 4 5 6 7 200 1 2 3 4 5 6 7\n"
    )
    assert rows == [{"interface": "eth0", "rx_bytes": 100, "tx_bytes": 200}]


def test_network_context_uses_structured_ip_output(tmp_path: Path) -> None:
    address_command = ("ip", "-j", "address", "show")
    route_command = ("ip", "-j", "route", "show", "default")
    runner = FakeRunner(
        responses={
            address_command: CommandResult(
                address_command,
                0,
                '[{"ifname":"eth0","operstate":"UP","mtu":1500,'
                '"addr_info":[{"local":"192.0.2.10","prefixlen":24}]}]',
                "",
            ),
            route_command: CommandResult(
                route_command,
                0,
                '[{"gateway":"192.0.2.1","dev":"eth0","metric":100}]',
                "",
            ),
        },
        executables={"ip"},
    )
    assert collect_network_interfaces(runner) == [
        {
            "name": "eth0",
            "state": "up",
            "mtu": 1500,
            "addresses": ["192.0.2.10/24"],
        }
    ]
    assert collect_default_routes(runner)[0]["gateway"] == "192.0.2.1"

    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "nameserver 1.1.1.1\nnameserver 2001:4860:4860::8888\nsearch example\n",
        encoding="utf-8",
    )
    assert collect_dns_servers(resolv) == ["1.1.1.1", "2001:4860:4860::8888"]
