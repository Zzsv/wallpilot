from __future__ import annotations

import json
import ipaddress
import os
import pathlib
import platform
import re
import shutil
import socket
import time
from datetime import UTC, datetime
from typing import Iterable

from .models import SystemMetrics, SystemProfile
from .runner import CommandRunner


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
            value = value.replace(r"\"", '"').replace(r"\\", "\\")
        values[key.strip()] = value
    return values


def read_os_release(path: pathlib.Path = pathlib.Path("/etc/os-release")) -> dict[str, str]:
    try:
        return parse_os_release(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}


def collect_profile(
    release: dict[str, str] | None = None,
    *,
    systemd_path: pathlib.Path = pathlib.Path("/run/systemd/system"),
) -> SystemProfile:
    release = release if release is not None else read_os_release()
    os_id = release.get("ID", platform.system().lower() or "unknown").lower()
    os_like = release.get("ID_LIKE", "").lower().split()
    try:
        timezone = datetime.now().astimezone().tzname() or "unknown"
    except Exception:
        timezone = "unknown"
    return SystemProfile(
        hostname=socket.gethostname(),
        os_id=os_id,
        os_like=os_like,
        os_name=release.get("PRETTY_NAME") or release.get("NAME") or platform.system(),
        os_version=release.get("VERSION_ID", ""),
        kernel=platform.release(),
        architecture=platform.machine(),
        systemd=systemd_path.exists(),
        timezone=timezone,
    )


def parse_meminfo(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        match = re.search(r"\d+", raw)
        if match:
            values[key] = int(match.group()) * 1024
    return values


def parse_loadavg(text: str) -> tuple[float, float, float]:
    fields = text.split()
    if len(fields) < 3:
        return (0.0, 0.0, 0.0)
    try:
        return (float(fields[0]), float(fields[1]), float(fields[2]))
    except ValueError:
        return (0.0, 0.0, 0.0)


def parse_net_dev(text: str) -> list[dict[str, int | str]]:
    items: list[dict[str, int | str]] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        fields = raw.split()
        if len(fields) < 9:
            continue
        try:
            items.append(
                {
                    "interface": name.strip(),
                    "rx_bytes": int(fields[0]),
                    "tx_bytes": int(fields[8]),
                }
            )
        except ValueError:
            continue
    return items


def _read_text(path: str) -> str:
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _disk_metrics(mounts: Iterable[str] = ("/",)) -> list[dict[str, int | str]]:
    items: list[dict[str, int | str]] = []
    seen: set[str] = set()
    for mount in mounts:
        if mount in seen or not pathlib.Path(mount).exists():
            continue
        seen.add(mount)
        try:
            usage = shutil.disk_usage(mount)
            row: dict[str, int | str] = {
                "mount": mount,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
            }
            if hasattr(os, "statvfs"):
                stat = os.statvfs(mount)
                row["inodes_total"] = stat.f_files
                row["inodes_free"] = stat.f_ffree
            items.append(row)
        except OSError:
            continue
    return items


def collect_metrics() -> SystemMetrics:
    mem = parse_meminfo(_read_text("/proc/meminfo"))
    load = parse_loadavg(_read_text("/proc/loadavg"))
    try:
        uptime = float((_read_text("/proc/uptime").split() or ["0"])[0])
    except ValueError:
        uptime = time.monotonic()
    return SystemMetrics(
        collected_at=datetime.now(UTC),
        uptime_seconds=uptime,
        load_1=load[0],
        load_5=load[1],
        load_15=load[2],
        cpu_count=os.cpu_count() or 0,
        memory_total=mem.get("MemTotal", 0),
        memory_available=mem.get("MemAvailable", mem.get("MemFree", 0)),
        swap_total=mem.get("SwapTotal", 0),
        swap_free=mem.get("SwapFree", 0),
        disks=_disk_metrics(),
        network=parse_net_dev(_read_text("/proc/net/dev")),
    )


def collect_failed_services(runner: CommandRunner) -> list[str]:
    if not runner.exists("systemctl"):
        return []
    result = runner.run(
        ["systemctl", "list-units", "--state=failed", "--type=service", "--no-legend", "--no-pager"]
    )
    if not result.ok:
        return []
    return [
        line.split()[0]
        for line in result.stdout.splitlines()
        if line.split() and line.split()[0].endswith(".service")
    ]


def collect_security_services(runner: CommandRunner) -> dict[str, str]:
    if not runner.exists("systemctl"):
        return {}
    candidates = (
        "ssh.service",
        "sshd.service",
        "fail2ban.service",
        "auditd.service",
        "systemd-timesyncd.service",
        "chronyd.service",
        "docker.service",
        "podman.service",
    )
    output: dict[str, str] = {}
    for unit in candidates:
        result = runner.run(["systemctl", "is-active", unit], allowed_returncodes=(0, 3, 4))
        state = result.stdout.strip()
        if state and state != "unknown":
            output[unit] = state
    return output


def collect_listeners(runner: CommandRunner) -> list[dict[str, str]]:
    if not runner.exists("ss"):
        return []
    result = runner.run(["ss", "-H", "-lntup"])
    if not result.ok:
        return []
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        process = " ".join(fields[6:]) if len(fields) > 6 else ""
        rows.append(
            {
                "protocol": fields[0],
                "local": fields[4],
                "process": process[:300],
            }
        )
    return rows


def collect_containers(runner: CommandRunner) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for engine in ("docker", "podman"):
        if not runner.exists(engine):
            continue
        result = runner.run(
            [
                engine,
                "ps",
                "--format",
                "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
            ]
        )
        if not result.ok:
            continue
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            fields += [""] * (4 - len(fields))
            rows.append(
                {
                    "engine": engine,
                    "name": fields[0],
                    "image": fields[1],
                    "status": fields[2],
                    "ports": fields[3],
                }
            )
    return rows


def collect_network_interfaces(runner: CommandRunner) -> list[dict[str, object]]:
    if not runner.exists("ip"):
        return []
    result = runner.run(["ip", "-j", "address", "show"])
    if not result.ok:
        return []
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    rows: list[dict[str, object]] = []
    for item in document if isinstance(document, list) else []:
        addresses = []
        for address in item.get("addr_info", []):
            local = address.get("local")
            prefix = address.get("prefixlen")
            if local is not None and prefix is not None:
                addresses.append(f"{local}/{prefix}")
        rows.append(
            {
                "name": str(item.get("ifname", "")),
                "state": str(item.get("operstate", "UNKNOWN")).lower(),
                "mtu": int(item.get("mtu", 0) or 0),
                "addresses": addresses,
            }
        )
    return rows


def collect_default_routes(runner: CommandRunner) -> list[dict[str, object]]:
    if not runner.exists("ip"):
        return []
    result = runner.run(["ip", "-j", "route", "show", "default"])
    if not result.ok:
        return []
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return [
        {
            "gateway": str(item.get("gateway", "")),
            "device": str(item.get("dev", "")),
            "metric": int(item.get("metric", 0) or 0),
            "protocol": str(item.get("protocol", "")),
        }
        for item in document
        if isinstance(item, dict)
    ]


def collect_dns_servers(
    path: pathlib.Path = pathlib.Path("/etc/resolv.conf"),
) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    servers: list[str] = []
    for raw in text.splitlines():
        fields = raw.split()
        if len(fields) != 2 or fields[0] != "nameserver":
            continue
        try:
            servers.append(str(ipaddress.ip_address(fields[1])))
        except ValueError:
            continue
    return servers


def collect_connections(runner: CommandRunner) -> list[dict[str, str]]:
    if not runner.exists("ss"):
        return []
    result = runner.run(["ss", "-H", "-ntup", "state", "established"])
    if not result.ok:
        return []
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        rows.append(
            {
                "protocol": fields[0],
                "local": fields[4],
                "remote": fields[5],
                "process": " ".join(fields[6:])[:300],
            }
        )
    return rows


def collect_ssh_sessions(runner: CommandRunner) -> list[dict[str, str]]:
    if not runner.exists("who"):
        return []
    result = runner.run(["who"])
    if not result.ok:
        return []
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        rows.append(
            {
                "user": fields[0],
                "terminal": fields[1],
                "since": " ".join(fields[2:4]),
                "source": " ".join(fields[4:]).strip("()"),
            }
        )
    return rows


def collect_security_modules(runner: CommandRunner) -> dict[str, str]:
    modules: dict[str, str] = {}
    if runner.exists("getenforce"):
        result = runner.run(["getenforce"])
        if result.ok and result.stdout.strip():
            modules["SELinux"] = result.stdout.strip()
    if runner.exists("aa-status"):
        result = runner.run(["aa-status", "--enabled"], allowed_returncodes=(0, 1))
        modules["AppArmor"] = "enabled" if result.returncode == 0 else "disabled"
    return modules


def reboot_required(
    path: pathlib.Path = pathlib.Path("/var/run/reboot-required"),
) -> bool:
    return path.exists()


def collect_security_update_cache() -> dict[str, str]:
    candidates = (
        (
            "apt",
            pathlib.Path("/var/lib/apt/lists"),
            pathlib.Path("/var/lib/update-notifier/updates-available"),
        ),
        ("dnf", pathlib.Path("/var/cache/dnf"), None),
        ("zypp", pathlib.Path("/var/cache/zypp"), None),
        ("pacman", pathlib.Path("/var/lib/pacman/sync"), None),
    )
    for source, directory, summary_path in candidates:
        if not directory.exists():
            continue
        try:
            modified = max(
                (path.stat().st_mtime for path in directory.iterdir()),
                default=directory.stat().st_mtime,
            )
            document = {
                "source": source,
                "last_cache_update": datetime.fromtimestamp(
                    modified, UTC
                ).isoformat(),
            }
            if summary_path and summary_path.exists():
                summary = " ".join(
                    summary_path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()[:3]
                ).strip()
                if summary:
                    document["summary"] = summary[:300]
            return document
        except OSError:
            continue
    return {"source": "unknown", "last_cache_update": "unknown"}
