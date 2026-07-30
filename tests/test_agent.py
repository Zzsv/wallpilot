from __future__ import annotations

from pathlib import Path

from wallpilot.agent import AgentServer, sign_request, verify_request


def test_agent_request_signature_detects_tampering() -> None:
    secret = bytes.fromhex("11" * 32)
    request = {
        "id": "one",
        "method": "service_action",
        "params": {"action": "restart"},
        "nonce": "random",
    }
    request["mac"] = sign_request(request, secret)
    assert verify_request(request, secret)
    request["params"]["action"] = "stop"
    assert not verify_request(request, secret)


def test_agent_nonce_cannot_be_replayed(tmp_path: Path) -> None:
    server = AgentServer(
        tmp_path / "agent.sock",
        bytes.fromhex("22" * 32),
        operations=object(),  # type: ignore[arg-type]
    )
    nonce = "ab" * 16
    assert server._accept_nonce(nonce)
    assert not server._accept_nonce(nonce)
    assert not server._accept_nonce("../not-a-valid-nonce")
