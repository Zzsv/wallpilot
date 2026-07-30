from __future__ import annotations

from wallpilot.firewall import FirewalldAdapter, UfwAdapter, adapter_for, detect_firewall
from wallpilot.models import BackendName, FirewallObject, FirewallRule
from wallpilot.runner import CommandResult, FakeRunner
from wallpilot.system_info import collect_profile


def result(argv: list[str], code: int, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(tuple(argv), code, stdout, stderr)


def test_detection_prefers_the_actually_active_backend() -> None:
    runner = FakeRunner(
        responses={
            ("firewall-cmd", "--state"): result(
                ["firewall-cmd", "--state"], 252, "", "not running"
            ),
            ("ufw", "status"): result(["ufw", "status"], 0, "Status: active\n"),
        },
        executables={"firewall-cmd", "ufw"},
    )
    profile = collect_profile({"ID": "ubuntu", "ID_LIKE": "debian"})
    detection = detect_firewall(profile, runner)
    assert detection.backend == BackendName.UFW
    assert detection.active_backends == [BackendName.UFW]


def test_detection_blocks_writes_when_multiple_backends_are_active() -> None:
    runner = FakeRunner(
        responses={
            ("firewall-cmd", "--state"): result(
                ["firewall-cmd", "--state"], 0, "running\n"
            ),
            ("ufw", "status"): result(["ufw", "status"], 0, "Status: active\n"),
        },
        executables={"firewall-cmd", "ufw"},
    )
    detection = detect_firewall(collect_profile({"ID": "ubuntu"}), runner)
    assert detection.conflict
    assert detection.backend == BackendName.CONFLICT


def test_non_systemd_environment_is_forced_read_only() -> None:
    runner = FakeRunner(
        responses={
            ("ufw", "status"): result(["ufw", "status"], 0, "Status: active\n"),
            ("ufw", "status", "verbose"): result(
                ["ufw", "status", "verbose"], 0, "Status: active\n"
            ),
        },
        executables={"ufw"},
    )
    profile = collect_profile({"ID": "ubuntu"})
    detection = detect_firewall(profile, runner)
    adapter = adapter_for(detection, runner, systemd=False)
    status = adapter.status()
    assert not status.capabilities.writable
    assert status.capabilities.service_actions == []


def test_native_nft_rules_are_detected_without_an_active_unit() -> None:
    command = ("nft", "--json", "list", "ruleset")
    runner = FakeRunner(
        responses={
            command: CommandResult(
                command,
                0,
                '{"nftables":[{"table":{"family":"inet","name":"filter"}}]}',
                "",
            ),
            ("systemctl", "is-active", "nftables.service"): CommandResult(
                ("systemctl", "is-active", "nftables.service"), 3, "inactive\n", ""
            ),
        },
        executables={"nft"},
    )
    detection = detect_firewall(collect_profile({"ID": "arch"}), runner)
    assert detection.backend == BackendName.NFTABLES
    assert detection.active_backends == [BackendName.NFTABLES]


def test_ufw_builds_argv_without_a_shell() -> None:
    expected = (
        "ufw",
        "allow",
        "in",
        "from",
        "192.168.1.0/24",
        "to",
        "any",
        "port",
        "443",
        "proto",
        "tcp",
        "comment",
        "web",
    )
    runner = FakeRunner(
        responses={expected: CommandResult(expected, 0, "", "")},
        executables={"ufw"},
    )
    adapter = UfwAdapter(runner)
    rule = FirewallRule(
        backend="ufw",
        action="allow",
        port="443",
        protocol="tcp",
        source="192.168.1.0/24",
        comment="web",
    )
    adapter.apply_rule("add", rule, permanent=False)
    assert runner.calls == [expected]
    assert all(";" not in argument for argument in runner.calls[0])


def test_ufw_route_rule_keeps_input_and_output_interfaces_separate() -> None:
    expected = (
        "ufw",
        "route",
        "allow",
        "in",
        "on",
        "eth0",
        "out",
        "on",
        "eth1",
        "from",
        "10.0.0.0/8",
        "to",
        "192.0.2.0/24",
        "port",
        "443",
        "proto",
        "tcp",
    )
    runner = FakeRunner(
        responses={expected: CommandResult(expected, 0, "", "")},
        executables={"ufw"},
    )
    rule = FirewallRule(
        backend="ufw",
        action="allow",
        direction="route",
        port="443",
        protocol="tcp",
        source="10.0.0.0/8",
        destination="192.0.2.0/24",
        interface_in="eth0",
        interface_out="eth1",
    )
    UfwAdapter(runner).apply_rule("add", rule, permanent=False)
    assert runner.calls == [expected]


def test_ufw_numbered_output_is_parsed() -> None:
    argv = ("ufw", "status", "numbered")
    runner = FakeRunner(
        responses={
            argv: CommandResult(
                argv,
                0,
                "[ 1] 22/tcp                     ALLOW IN    10.0.0.0/8\n"
                "[ 2] 53/udp                     DENY IN     Anywhere\n",
                "",
            )
        },
        executables={"ufw"},
    )
    rules = UfwAdapter(runner).list_rules()
    assert [(rule.port, rule.action.value, rule.source) for rule in rules] == [
        ("22", "allow", "10.0.0.0/8"),
        ("53", "deny", None),
    ]


def test_ufw_ipv6_duplicate_and_comment_are_normalized() -> None:
    argv = ("ufw", "status", "numbered")
    runner = FakeRunner(
        responses={
            argv: CommandResult(
                argv,
                0,
                "[ 1] 443/tcp ALLOW IN Anywhere # web\n"
                "[ 2] 443/tcp (v6) ALLOW IN Anywhere (v6) # web\n",
                "",
            )
        },
        executables={"ufw"},
    )
    rules = UfwAdapter(runner).list_rules()
    assert len(rules) == 1
    assert rules[0].comment == "web"
    assert rules[0].metadata["ufw_number"] == 1


def test_ufw_existing_rule_delete_reuses_validated_semantic_rule() -> None:
    command = (
        "ufw",
        "--force",
        "delete",
        "allow",
        "in",
        "from",
        "any",
        "to",
        "any",
        "port",
        "22",
        "proto",
        "tcp",
        "comment",
        "remote access",
    )
    runner = FakeRunner(
        responses={command: CommandResult(command, 0, "", "")},
        executables={"ufw"},
    )
    rule = FirewallRule(
        backend="ufw",
        port="22",
        protocol="tcp",
        comment="remote access",
        metadata={"ufw_number": 12},
    )
    UfwAdapter(runner).apply_rule("delete", rule, permanent=False)
    assert runner.calls == [command]


class FakeFirewalldDBus:
    def __init__(self) -> None:
        self.reloads = 0

    def reload(self) -> None:
        self.reloads += 1


class FakeRuleDBus:
    def __init__(self) -> None:
        self.changes: list[tuple[object, ...]] = []

    def default_zone(self) -> str:
        return "public"

    def change_rich_rule(self, *args: object) -> None:
        self.changes.append(args)


def test_firewalld_restricted_source_is_a_structured_rich_rule() -> None:
    dbus = FakeRuleDBus()
    rule = FirewallRule(
        backend="firewalld",
        action="deny",
        port="5432",
        protocol="tcp",
        source="0.0.0.0/0",
        destination="192.0.2.10/32",
        temporary_seconds=120,
    )
    FirewalldAdapter(FakeRunner(), dbus_client=dbus).apply_rule(
        "add", rule, permanent=False
    )
    assert dbus.changes == [
        (
            "public",
            'rule family="ipv4" source address="0.0.0.0/0" '
            'destination address="192.0.2.10/32" '
            'port port="5432" protocol="tcp" drop',
            "add",
            False,
            120,
        )
    ]


def test_firewalld_custom_service_uses_fixed_firewall_cmd_arguments() -> None:
    commands = [
        ("firewall-cmd", "--permanent", "--new-service=wallpilot-web"),
        (
            "firewall-cmd",
            "--permanent",
            "--service=wallpilot-web",
            "--set-short=WallPilot Web",
        ),
        (
            "firewall-cmd",
            "--permanent",
            "--service=wallpilot-web",
            "--add-port=8443/tcp",
        ),
    ]
    runner = FakeRunner(
        responses={
            command: CommandResult(command, 0, "", "") for command in commands
        },
        executables={"firewall-cmd"},
    )
    dbus = FakeFirewalldDBus()
    item = FirewallObject(
        object_type="service",
        name="wallpilot-web",
        settings={
            "short": "WallPilot Web",
            "ports": [{"port": "8443", "protocol": "tcp"}],
        },
    )
    FirewalldAdapter(runner, dbus_client=dbus).apply_object("add", item)
    assert runner.calls == commands
    assert dbus.reloads == 1
    assert all(
        ";" not in argument and "\n" not in argument
        for command in runner.calls
        for argument in command
    )


def test_firewalld_ipset_uses_explicit_family_and_safe_entries() -> None:
    commands = [
        (
            "firewall-cmd",
            "--permanent",
            "--new-ipset=blocked-hosts",
            "--type=hash:ip",
            "--family=inet",
            "--option=hashsize=1024",
            "--option=maxelem=65536",
        ),
        (
            "firewall-cmd",
            "--permanent",
            "--ipset=blocked-hosts",
            "--add-entry=192.0.2.10",
        ),
    ]
    runner = FakeRunner(
        responses={
            command: CommandResult(command, 0, "", "") for command in commands
        },
        executables={"firewall-cmd"},
    )
    dbus = FakeFirewalldDBus()
    item = FirewallObject(
        object_type="ipset",
        name="blocked-hosts",
        settings={"entries": ["192.0.2.10"]},
    )
    FirewalldAdapter(runner, dbus_client=dbus).apply_object("add", item)
    assert runner.calls == commands
    assert dbus.reloads == 1
