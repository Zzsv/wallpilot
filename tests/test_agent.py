from __future__ import annotations

from wallpilot.agent import sign_request, verify_request


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

