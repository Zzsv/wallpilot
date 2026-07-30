from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import quote

from .config import Settings
from .control import ControlPlane
from .doctor import collect_doctor_report, render_doctor_report
from .storage import Store


def _objects() -> tuple[Settings, Store, ControlPlane]:
    settings = Settings()
    store = Store(settings)
    remote_adapter = None
    if (
        os.name == "posix"
        and settings.agent_socket.exists()
        and settings.agent_key_path.exists()
    ):
        try:
            from .agent_client import AgentClient, RemoteFirewallAdapter

            remote_adapter = RemoteFirewallAdapter(AgentClient(settings))
        except Exception:
            remote_adapter = None
    return settings, store, ControlPlane(settings, store, adapter=remote_adapter)


def command_bootstrap() -> int:
    settings, store, control = _objects()
    path = settings.ensure_access_path()
    if store.is_initialized():
        print("WallPilot 已经完成初始化。")
        print(f"管理地址：http://127.0.0.1:{settings.bind_port}/manage/{path}/")
        return 0
    bootstrap = store.ensure_bootstrap()
    issuer = quote("WallPilot")
    label = quote(f"WallPilot:admin@{control.hostname}")
    uri = (
        f"otpauth://totp/{label}?secret={bootstrap['totp_secret']}"
        f"&issuer={issuer}&digits=6&period=30"
    )
    print(f"管理地址：http://127.0.0.1:{settings.bind_port}/manage/{path}/")
    print(f"引导令牌：{bootstrap['token']}")
    print(f"TOTP 密钥：{bootstrap['totp_secret']}")
    print(f"TOTP URI：{uri}")
    print(f"有效期：{bootstrap['expires']}")
    return 0


def command_status(as_json: bool) -> int:
    _settings, _store, control = _objects()
    document = control.server_status()
    if as_json:
        print(json.dumps(document, ensure_ascii=False, indent=2))
    else:
        profile = document["profile"]
        firewall = document["firewall"]
        print(f"{profile['os_name']} {profile['os_version']} · {profile['kernel']}")
        print(
            f"防火墙：{firewall['backend']} · "
            f"{'运行中' if firewall['active'] else '未运行'}"
        )
        print(f"告警：{len(document['alerts'])}")
    return 0


def command_doctor(as_json: bool) -> int:
    report = collect_doctor_report()
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_doctor_report(report))
    return 0 if report["healthy"] else 1


def command_serve() -> int:
    settings = Settings()
    import uvicorn

    uvicorn.run(
        "wallpilot.app:app",
        host=settings.bind_host,
        port=settings.bind_port,
        proxy_headers=False,
        server_header=False,
    )
    return 0


def command_emergency_start() -> int:
    _settings, _store, control = _objects()
    control.emergency_start()
    print("防火墙启动请求已完成。")
    return 0


def command_emergency_rollback() -> int:
    _settings, _store, control = _objects()
    rolled = control.emergency_rollback()
    print(f"已回滚 {len(rolled)} 个待确认操作。")
    return 0


def command_rotate_path() -> int:
    settings, _store, _control = _objects()
    value = settings.rotate_access_path()
    print(f"新的管理地址：http://127.0.0.1:{settings.bind_port}/manage/{value}/")
    print("请重启 wallpilot-web.service 使新地址生效。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WallPilot Linux 防火墙管理面板")
    parser.add_argument("--version", action="version", version="WallPilot 0.1.0")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="启动 Web 服务")
    sub.add_parser("bootstrap", help="显示首次初始化信息")
    status_parser = sub.add_parser("status", help="显示服务器和防火墙状态")
    status_parser.add_argument("--json", action="store_true")
    doctor_parser = sub.add_parser("doctor", help="检查安装、安全配置和访问条件")
    doctor_parser.add_argument("--json", action="store_true")
    sub.add_parser("emergency-start", help="紧急启动防火墙")
    sub.add_parser("emergency-rollback", help="回滚所有待确认操作")
    sub.add_parser("rotate-path", help="轮换随机管理路径")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "serve":
            return command_serve()
        if args.command == "bootstrap":
            return command_bootstrap()
        if args.command == "status":
            return command_status(args.json)
        if args.command == "doctor":
            return command_doctor(args.json)
        if args.command == "emergency-start":
            return command_emergency_start()
        if args.command == "emergency-rollback":
            return command_emergency_rollback()
        if args.command == "rotate-path":
            return command_rotate_path()
        build_parser().print_help()
        return 0
    except PermissionError:
        print("权限不足；服务控制和系统级状态需要 root 代理。", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"WallPilot 操作失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
