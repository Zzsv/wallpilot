from __future__ import annotations

import json
from pathlib import Path

from wallpilot.cli import build_parser
from wallpilot.config import Settings
from wallpilot.doctor import collect_doctor_report, render_doctor_report
from wallpilot.models import SystemProfile
from wallpilot.runner import CommandResult, FakeRunner


def _profile(*, systemd: bool = True) -> SystemProfile:
    return SystemProfile(
        hostname="wallpilot-test",
        os_id="ubuntu",
        os_like=["debian"],
        os_name="Ubuntu",
        os_version="24.04",
        kernel="6.8.0",
        architecture="x86_64",
        systemd=systemd,
        timezone="UTC",
    )


def _settings(tmp_path: Path, *, bind_host: str = "127.0.0.1") -> Settings:
    return Settings(
        state_dir=tmp_path / "state",
        bind_host=bind_host,
        agent_socket=tmp_path / "agent.sock",
    )


def test_doctor_detects_backend_conflict_without_exposing_secrets(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.ensure_directories()
    settings.agent_key_path.write_text("a" * 64, encoding="ascii")
    settings.access_path_file.write_text("S" * 43, encoding="utf-8")
    responses = {
        ("firewall-cmd", "--state"): CommandResult(
            ("firewall-cmd", "--state"), 0, "running\n", ""
        ),
        ("ufw", "status"): CommandResult(
            ("ufw", "status"), 0, "Status: active\n", ""
        ),
    }
    runner = FakeRunner(
        responses=responses,
        executables={"firewall-cmd", "ufw"},
    )

    report = collect_doctor_report(
        settings,
        runner=runner,
        profile=_profile(),
        platform_name="linux",
        python_version=(3, 10),
        account_exists=True,
    )

    assert report["firewall"]["conflict"] is True
    assert report["healthy"] is False
    assert any(
        check["id"] == "firewall-backend" and check["status"] == "fail"
        for check in report["checks"]
    )
    serialized = json.dumps(report, ensure_ascii=False)
    assert "S" * 43 not in serialized
    assert "a" * 64 not in serialized


def test_doctor_flags_public_bind_and_missing_installation(tmp_path: Path) -> None:
    report = collect_doctor_report(
        _settings(tmp_path, bind_host="0.0.0.0"),
        runner=FakeRunner(),
        profile=_profile(systemd=False),
        platform_name="linux",
        python_version=(3, 10),
        account_exists=False,
    )

    checks = {check["id"]: check for check in report["checks"]}
    assert checks["bind-address"]["status"] == "fail"
    assert checks["state-directory"]["status"] == "fail"
    assert checks["systemd"]["status"] == "fail"
    assert "WALLPILOT_HOST" in checks["bind-address"]["remediation"]


def test_doctor_renderer_and_cli_parser() -> None:
    report = {
        "profile": {"os": "Ubuntu", "version": "24.04", "architecture": "x86_64"},
        "firewall": {"selected": "ufw"},
        "summary": {"pass": 1, "warn": 0, "fail": 0},
        "checks": [
            {
                "id": "python",
                "status": "pass",
                "title": "Python 版本",
                "detail": "Python 3.10",
                "remediation": "",
            }
        ],
    }
    rendered = render_doctor_report(report)
    assert "[通过] Python 版本" in rendered
    assert "1 项通过" in rendered

    args = build_parser().parse_args(["doctor", "--json"])
    assert args.command == "doctor"
    assert args.json is True
