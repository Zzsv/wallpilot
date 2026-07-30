from __future__ import annotations

from wallpilot.firewall import UfwAdapter, detect_firewall
from wallpilot.models import BackendName, FirewallRule
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

