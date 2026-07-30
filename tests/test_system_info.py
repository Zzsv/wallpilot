from __future__ import annotations

from wallpilot.system_info import (
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

