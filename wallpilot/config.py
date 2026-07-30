from __future__ import annotations

import os
import pathlib
import secrets
import tempfile
from dataclasses import dataclass, field


def _default_state_dir() -> pathlib.Path:
    configured = os.environ.get("WALLPILOT_STATE_DIR")
    if configured:
        return pathlib.Path(configured)
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        return pathlib.Path("/var/lib/wallpilot")
    if os.name != "posix":
        return pathlib.Path(tempfile.gettempdir()) / "wallpilot-dev"
    return pathlib.Path.cwd() / "wallpilot-state"


@dataclass(slots=True)
class Settings:
    state_dir: pathlib.Path = field(default_factory=_default_state_dir)
    bind_host: str = field(
        default_factory=lambda: os.environ.get("WALLPILOT_HOST", "127.0.0.1")
    )
    bind_port: int = field(
        default_factory=lambda: int(os.environ.get("WALLPILOT_PORT", "8787"))
    )
    apply_timeout_seconds: int = field(
        default_factory=lambda: int(os.environ.get("WALLPILOT_APPLY_TIMEOUT", "90"))
    )
    session_idle_seconds: int = 15 * 60
    session_absolute_seconds: int = 8 * 60 * 60
    bootstrap_lifetime_seconds: int = 15 * 60
    agent_socket: pathlib.Path = field(
        default_factory=lambda: pathlib.Path(
            os.environ.get("WALLPILOT_AGENT_SOCKET", "/run/wallpilot/agent.sock")
        )
    )
    allowed_hosts: tuple[str, ...] = (
        "127.0.0.1",
        "localhost",
        "[::1]",
        "testserver",
    )

    @property
    def database_path(self) -> pathlib.Path:
        return self.state_dir / "wallpilot.db"

    @property
    def bootstrap_path(self) -> pathlib.Path:
        return self.state_dir / "bootstrap.txt"

    @property
    def recycle_dir(self) -> pathlib.Path:
        return self.state_dir / "recycle"

    @property
    def agent_key_path(self) -> pathlib.Path:
        configured = os.environ.get("WALLPILOT_AGENT_KEY")
        return pathlib.Path(configured) if configured else self.state_dir / "agent.key"

    @property
    def access_path_file(self) -> pathlib.Path:
        return self.state_dir / "access-path"

    def ensure_directories(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.recycle_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.state_dir, 0o700)
            os.chmod(self.recycle_dir, 0o700)

    def ensure_access_path(self) -> str:
        self.ensure_directories()
        if self.access_path_file.exists():
            value = self.access_path_file.read_text(encoding="utf-8").strip()
            if value and all(ch.isalnum() or ch in "-_" for ch in value):
                return value
        value = secrets.token_urlsafe(32)
        self.access_path_file.write_text(value + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.access_path_file, 0o600)
        return value

    def rotate_access_path(self) -> str:
        self.ensure_directories()
        value = secrets.token_urlsafe(32)
        self.access_path_file.write_text(value + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.access_path_file, 0o600)
        return value
