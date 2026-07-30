from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import socket
import struct
from typing import Any

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - agent only runs on Linux
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

from .config import Settings
from .firewall import adapter_for, detect_firewall
from .models import FirewallRule, ServiceAction
from .runner import CommandRunner
from .security import secure_file_mode
from .system_info import collect_profile


MAX_REQUEST_BYTES = 1024 * 1024
ALLOWED_METHODS = {
    "firewall_status",
    "rules",
    "snapshot",
    "apply_rule",
    "service_action",
}


def canonical_request(document: dict[str, Any]) -> bytes:
    signed = {
        "id": document.get("id"),
        "method": document.get("method"),
        "nonce": document.get("nonce"),
        "params": document.get("params", {}),
    }
    return json.dumps(
        signed, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_request(document: dict[str, Any], secret: bytes) -> str:
    return hmac.new(secret, canonical_request(document), hashlib.sha256).hexdigest()


def verify_request(document: dict[str, Any], secret: bytes) -> bool:
    provided = str(document.get("mac", ""))
    return bool(provided) and hmac.compare_digest(provided, sign_request(document, secret))


def load_or_create_agent_key(settings: Settings) -> bytes:
    path = settings.agent_key_path
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = path.read_text(encoding="ascii").strip()
        return bytes.fromhex(raw)
    secret = secrets.token_bytes(32)
    path.write_text(secret.hex() + "\n", encoding="ascii")
    secure_file_mode(path)
    if pwd is not None and grp is not None:
        try:
            os.chown(path, 0, grp.getgrnam("wallpilot").gr_gid)
            os.chmod(path, 0o640)
        except KeyError:
            pass
    return secret


class AgentOperations:
    def __init__(self) -> None:
        self.runner = CommandRunner()
        self.profile = collect_profile()
        self.detection = detect_firewall(self.profile, self.runner)
        self.adapter = adapter_for(self.detection, self.runner)

    def refresh(self) -> None:
        detection = detect_firewall(self.profile, self.runner)
        if detection.backend != self.detection.backend or detection.conflict != self.detection.conflict:
            self.detection = detection
            self.adapter = adapter_for(detection, self.runner)

    def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        if method not in ALLOWED_METHODS:
            raise ValueError("agent method is not allowed")
        self.refresh()
        if method == "firewall_status":
            return self.adapter.status().model_dump(mode="json")
        if method == "rules":
            return [rule.model_dump(mode="json") for rule in self.adapter.list_rules()]
        if method == "snapshot":
            return {
                "profile": self.profile.model_dump(mode="json"),
                "firewall": self.adapter.status().model_dump(mode="json"),
                "rules": [rule.model_dump(mode="json") for rule in self.adapter.list_rules()],
            }
        if method == "apply_rule":
            operation = str(params.get("operation", ""))
            if operation not in {"add", "delete", "restore"}:
                raise ValueError("unsupported rule operation")
            rule = FirewallRule.model_validate(params.get("rule"))
            if rule.backend != self.adapter.backend:
                raise ValueError("rule backend mismatch")
            self.adapter.apply_rule(
                operation,
                rule,
                permanent=bool(params.get("permanent", False)),
            )
            return {"status": "ok"}
        if method == "service_action":
            action = ServiceAction(str(params.get("action", "")))
            self.adapter.service_action(action)
            return {"status": "ok"}
        raise ValueError("unreachable")


class AgentServer:
    def __init__(
        self,
        socket_path: pathlib.Path,
        secret: bytes,
        operations: AgentOperations | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.secret = secret
        self.operations = operations or AgentOperations()
        self.allowed_uids = {0}
        if pwd is not None:
            try:
                self.allowed_uids.add(pwd.getpwnam("wallpilot").pw_uid)
            except KeyError:
                pass

    def _peer_allowed(self, writer: asyncio.StreamWriter) -> bool:
        if os.name != "posix":
            return False
        peer_socket = writer.get_extra_info("socket")
        if peer_socket is None or not hasattr(socket, "SO_PEERCRED"):
            return False
        credentials = peer_socket.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _pid, uid, _gid = struct.unpack("3i", credentials)
        return uid in self.allowed_uids

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        response: dict[str, Any]
        try:
            if not self._peer_allowed(writer):
                raise PermissionError("unix peer is not allowed")
            raw = await reader.readline()
            if not raw or len(raw) > MAX_REQUEST_BYTES:
                raise ValueError("invalid agent request size")
            document = json.loads(raw)
            if not verify_request(document, self.secret):
                raise PermissionError("agent request signature mismatch")
            method = str(document.get("method", ""))
            params = document.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("agent params must be an object")
            result = await asyncio.to_thread(self.operations.dispatch, method, params)
            response = {"id": document.get("id"), "ok": True, "result": result}
        except Exception as exc:
            response = {
                "id": None,
                "ok": False,
                "error": type(exc).__name__,
                "detail": str(exc),
            }
        writer.write(
            json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def serve(self) -> None:
        if os.name != "posix":
            raise RuntimeError("WallPilot agent requires a Unix domain socket")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        server = await asyncio.start_unix_server(self.handle, path=self.socket_path)
        os.chmod(self.socket_path, 0o660)
        if grp is not None:
            try:
                os.chown(self.socket_path, 0, grp.getgrnam("wallpilot").gr_gid)
            except KeyError:
                pass
        async with server:
            await server.serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WallPilot privileged firewall agent")
    parser.add_argument("--socket", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings()
    secret = load_or_create_agent_key(settings)
    server = AgentServer(args.socket or settings.agent_socket, secret)
    asyncio.run(server.serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
