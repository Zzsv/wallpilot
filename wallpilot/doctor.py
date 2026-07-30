from __future__ import annotations

import os
import pathlib
import stat
import sys
from dataclasses import asdict, dataclass
from typing import Any, Literal

from .config import Settings
from .firewall import detect_firewall
from .models import BackendName, SystemProfile
from .runner import CommandRunner
from .system_info import collect_profile


CheckStatus = Literal["pass", "warn", "fail"]


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    id: str
    status: CheckStatus
    title: str
    detail: str
    remediation: str = ""


def _file_mode(path: pathlib.Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def _service_active(runner: CommandRunner, unit: str) -> bool:
    result = runner.run(
        ["systemctl", "is-active", unit],
        allowed_returncodes=(0, 3, 4),
    )
    return result.stdout.strip() == "active"


def _wallpilot_account_exists() -> bool | None:
    if os.name != "posix":
        return None
    try:
        import pwd

        pwd.getpwnam("wallpilot")
        return True
    except KeyError:
        return False
    except ImportError:
        return None


def collect_doctor_report(
    settings: Settings | None = None,
    *,
    runner: CommandRunner | None = None,
    profile: SystemProfile | None = None,
    platform_name: str | None = None,
    python_version: tuple[int, int] | None = None,
    account_exists: bool | None = None,
) -> dict[str, Any]:
    """Collect read-only installation diagnostics without exposing secrets."""

    settings = settings or Settings()
    runner = runner or CommandRunner()
    profile = profile or collect_profile()
    platform_name = platform_name or sys.platform
    python_version = python_version or sys.version_info[:2]
    if account_exists is None:
        account_exists = _wallpilot_account_exists()

    checks: list[DoctorCheck] = []

    def add(
        check_id: str,
        status: CheckStatus,
        title: str,
        detail: str,
        remediation: str = "",
    ) -> None:
        checks.append(DoctorCheck(check_id, status, title, detail, remediation))

    if platform_name.startswith("linux"):
        add("platform", "pass", "Linux 系统", f"检测到 {profile.os_name}")
    else:
        add(
            "platform",
            "fail",
            "Linux 系统",
            f"当前平台为 {platform_name}",
            "请在受支持的 Linux 服务器上运行 WallPilot。",
        )

    if python_version >= (3, 10):
        add(
            "python",
            "pass",
            "Python 版本",
            f"Python {python_version[0]}.{python_version[1]}",
        )
    else:
        add(
            "python",
            "fail",
            "Python 版本",
            f"Python {python_version[0]}.{python_version[1]} 版本过低",
            "请安装 Python 3.10 或更高版本。",
        )

    if profile.systemd:
        add("systemd", "pass", "systemd", "systemd 正在运行")
    else:
        add(
            "systemd",
            "fail",
            "systemd",
            "未检测到运行中的 systemd",
            "当前版本仅在 systemd 系统上提供服务控制。",
        )

    detection = detect_firewall(profile, runner)
    installed = [backend.value for backend in detection.installed_backends]
    active = [backend.value for backend in detection.active_backends]
    if detection.conflict:
        add(
            "firewall-backend",
            "fail",
            "防火墙后端",
            f"多个后端同时活动：{', '.join(active)}",
            "请只保留一个活动防火墙后端，再重新运行诊断。",
        )
    elif detection.backend == BackendName.NONE:
        add(
            "firewall-backend",
            "fail",
            "防火墙后端",
            "未检测到受支持的防火墙",
            "请安装并启用 firewalld 或 UFW。",
        )
    elif detection.backend in {BackendName.NFTABLES, BackendName.IPTABLES}:
        add(
            "firewall-backend",
            "warn",
            "防火墙后端",
            f"检测到只读后端 {detection.backend.value}",
            "如需 Web 写入规则，请改用 firewalld 或 UFW。",
        )
    else:
        add(
            "firewall-backend",
            "pass",
            "防火墙后端",
            f"检测到 {detection.backend.value}",
        )

    if active:
        add(
            "firewall-active",
            "pass",
            "防火墙运行状态",
            f"活动后端：{', '.join(active)}",
        )
    elif detection.backend != BackendName.NONE:
        add(
            "firewall-active",
            "warn",
            "防火墙运行状态",
            f"{detection.backend.value} 已安装但未确认处于活动状态",
            "请先从云控制台确认恢复通道，再启用防火墙。",
        )

    if account_exists is True:
        add("service-account", "pass", "服务账户", "wallpilot 用户存在")
    elif account_exists is False:
        add(
            "service-account",
            "fail",
            "服务账户",
            "wallpilot 用户不存在",
            "请重新运行官方安装程序。",
        )
    else:
        add(
            "service-account",
            "warn",
            "服务账户",
            "当前平台无法检查 wallpilot 用户",
        )

    if not settings.state_dir.exists():
        add(
            "state-directory",
            "fail",
            "状态目录",
            f"{settings.state_dir} 不存在",
            "请重新运行官方安装程序。",
        )
    elif not settings.state_dir.is_dir():
        add(
            "state-directory",
            "fail",
            "状态目录",
            f"{settings.state_dir} 不是目录",
            "请移走冲突文件并重新运行官方安装程序。",
        )
    else:
        mode = _file_mode(settings.state_dir)
        if mode is not None and mode & 0o077:
            add(
                "state-directory",
                "fail",
                "状态目录权限",
                f"{settings.state_dir} 权限为 {mode:04o}",
                f"请执行 chmod 0700 {settings.state_dir}。",
            )
        else:
            add(
                "state-directory",
                "pass",
                "状态目录权限",
                f"{settings.state_dir} 未向其他用户开放",
            )

    key_path = settings.agent_key_path
    if not key_path.is_file():
        add(
            "agent-key",
            "fail",
            "代理密钥",
            "代理密钥不存在或不是普通文件",
            "请启动 wallpilot-agent.service 生成受限密钥。",
        )
    else:
        mode = _file_mode(key_path)
        unsafe = mode is not None and bool(mode & 0o137)
        if unsafe:
            add(
                "agent-key",
                "fail",
                "代理密钥权限",
                f"代理密钥权限为 {mode:04o}",
                "请将密钥设为 root:wallpilot 所有、权限 0640。",
            )
        else:
            add("agent-key", "pass", "代理密钥权限", "密钥未向其他用户开放")

    socket_path = settings.agent_socket
    if not socket_path.exists():
        add(
            "agent-socket",
            "fail",
            "root 代理 Socket",
            f"{socket_path} 不存在",
            "请执行 systemctl restart wallpilot-agent.service。",
        )
    elif not socket_path.is_socket():
        add(
            "agent-socket",
            "fail",
            "root 代理 Socket",
            f"{socket_path} 不是 Unix Socket",
            "请停止服务、移走冲突文件并重新启动代理。",
        )
    else:
        mode = _file_mode(socket_path)
        if mode is not None and mode & 0o007:
            add(
                "agent-socket",
                "fail",
                "root 代理 Socket 权限",
                f"Socket 权限为 {mode:04o}",
                "请重启代理并确认 Socket 权限为 0660。",
            )
        else:
            add("agent-socket", "pass", "root 代理 Socket", "Unix Socket 可用")

    if profile.systemd and runner.exists("systemctl"):
        missing_units = [
            unit
            for unit in ("wallpilot-agent.service", "wallpilot-web.service")
            if not _service_active(runner, unit)
        ]
        if missing_units:
            add(
                "wallpilot-services",
                "fail",
                "WallPilot 服务",
                f"未运行：{', '.join(missing_units)}",
                "请执行 systemctl enable --now wallpilot-agent.service wallpilot-web.service。",
            )
        else:
            add("wallpilot-services", "pass", "WallPilot 服务", "两个服务均在运行")

        ssh_active = any(
            _service_active(runner, unit) for unit in ("ssh.service", "sshd.service")
        )
        if ssh_active:
            add("ssh-tunnel", "pass", "SSH 隧道", "SSH 服务正在运行")
        else:
            add(
                "ssh-tunnel",
                "warn",
                "SSH 隧道",
                "未确认 ssh.service 或 sshd.service 处于活动状态",
                "请确认服务器 SSH 服务和云安全组允许你的管理来源。",
            )
    else:
        add(
            "wallpilot-services",
            "warn",
            "WallPilot 服务",
            "无法通过 systemctl 检查服务状态",
        )

    if settings.bind_host in {"127.0.0.1", "::1", "localhost"}:
        add(
            "bind-address",
            "pass",
            "Web 监听地址",
            f"仅监听回环地址 {settings.bind_host}:{settings.bind_port}",
        )
    else:
        add(
            "bind-address",
            "fail",
            "Web 监听地址",
            f"当前监听地址为 {settings.bind_host}:{settings.bind_port}",
            "请将 WALLPILOT_HOST 改为 127.0.0.1，并通过 SSH 隧道访问。",
        )

    access_path = settings.access_path_file
    if not access_path.is_file():
        add(
            "access-path",
            "fail",
            "随机管理路径",
            "随机管理路径文件不存在",
            "请运行 wallpilot bootstrap 生成初始化信息。",
        )
    else:
        try:
            value = access_path.read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        mode = _file_mode(access_path)
        secure_value = (
            len(value) >= 43
            and all(character.isalnum() or character in "-_" for character in value)
        )
        if not secure_value or (mode is not None and mode & 0o077):
            add(
                "access-path",
                "fail",
                "随机管理路径",
                "随机路径内容或文件权限不符合安全要求",
                "请运行 wallpilot rotate-path 后重启 Web 服务。",
            )
        else:
            add(
                "access-path",
                "pass",
                "随机管理路径",
                "随机路径存在且未在诊断结果中显示",
            )

    counts = {
        status: sum(check.status == status for check in checks)
        for status in ("pass", "warn", "fail")
    }
    return {
        "healthy": counts["fail"] == 0,
        "profile": {
            "hostname": profile.hostname,
            "os": profile.os_name,
            "version": profile.os_version,
            "kernel": profile.kernel,
            "architecture": profile.architecture,
        },
        "firewall": {
            "selected": detection.backend.value,
            "installed": installed,
            "active": active,
            "conflict": detection.conflict,
        },
        "summary": counts,
        "checks": [asdict(check) for check in checks],
    }


def render_doctor_report(report: dict[str, Any]) -> str:
    labels = {"pass": "通过", "warn": "警告", "fail": "失败"}
    lines = [
        "WallPilot 环境诊断",
        (
            f"系统：{report['profile']['os']} {report['profile']['version']} · "
            f"{report['profile']['architecture']}"
        ),
        f"防火墙：{report['firewall']['selected']}",
        "",
    ]
    for check in report["checks"]:
        lines.append(f"[{labels[check['status']]}] {check['title']}：{check['detail']}")
        if check["remediation"]:
            lines.append(f"  建议：{check['remediation']}")
    summary = report["summary"]
    lines.extend(
        [
            "",
            (
                f"汇总：{summary['pass']} 项通过，{summary['warn']} 项警告，"
                f"{summary['fail']} 项失败"
            ),
        ]
    )
    return "\n".join(lines)
