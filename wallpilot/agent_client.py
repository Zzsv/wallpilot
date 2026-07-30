from __future__ import annotations

import json
import secrets
import socket
import uuid
from typing import Any

from .agent import MAX_REQUEST_BYTES, sign_request
from .config import Settings
from .firewall import FirewallAdapter, FirewallError
from .models import (
    BackendName,
    FirewallObject,
    FirewallRule,
    FirewallStatus,
    ServiceAction,
)


class AgentClient:
    def __init__(self, settings: Settings) -> None:
        self.socket_path = settings.agent_socket
        self.secret = bytes.fromhex(
            settings.agent_key_path.read_text(encoding="ascii").strip()
        )

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        request_id = str(uuid.uuid4())
        document = {
            "id": request_id,
            "method": method,
            "params": params or {},
            "nonce": secrets.token_hex(16),
        }
        document["mac"] = sign_request(document, self.secret)
        raw = json.dumps(
            document, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        if len(raw) > MAX_REQUEST_BYTES:
            raise FirewallError("agent request is too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(15)
            client.connect(str(self.socket_path))
            client.sendall(raw)
            response = b""
            while not response.endswith(b"\n"):
                chunk = client.recv(65536)
                if not chunk:
                    break
                response += chunk
                if len(response) > MAX_REQUEST_BYTES:
                    raise FirewallError("agent response is too large")
        document = json.loads(response)
        if document.get("id") != request_id:
            raise FirewallError("agent response id mismatch")
        if not document.get("ok"):
            raise FirewallError(str(document.get("detail") or "agent operation failed"))
        return document.get("result")


class RemoteFirewallAdapter(FirewallAdapter):
    def __init__(self, client: AgentClient) -> None:
        super().__init__(runner=None)  # type: ignore[arg-type]
        self.client = client
        status = FirewallStatus.model_validate(client.call("firewall_status"))
        self.backend = BackendName(status.backend)

    def status(self) -> FirewallStatus:
        status = FirewallStatus.model_validate(self.client.call("firewall_status"))
        self.backend = BackendName(status.backend)
        return status

    def list_rules(self) -> list[FirewallRule]:
        return [
            FirewallRule.model_validate(item)
            for item in self.client.call("rules")
        ]

    def apply_rule(self, operation: str, rule: FirewallRule, *, permanent: bool) -> None:
        self.client.call(
            "apply_rule",
            {
                "operation": operation,
                "rule": rule.model_dump(mode="json"),
                "permanent": permanent,
            },
        )

    def service_action(self, action: ServiceAction) -> None:
        self.client.call("service_action", {"action": action.value})

    def list_objects(self) -> list[dict[str, Any]]:
        return list(self.client.call("objects"))

    def rejection_logs(self, limit: int = 200) -> list[str]:
        return [
            str(value)
            for value in self.client.call(
                "logs", {"limit": min(max(limit, 1), 500)}
            )
        ]

    def get_object(self, object_type: str, name: str) -> FirewallObject:
        return FirewallObject.model_validate(
            self.client.call(
                "get_object", {"object_type": object_type, "name": name}
            )
        )

    def apply_object(
        self,
        operation: str,
        item: FirewallObject,
        *,
        before: FirewallObject | None = None,
    ) -> None:
        self.client.call(
            "apply_object",
            {
                "operation": operation,
                "object": item.model_dump(mode="json"),
                "before": before.model_dump(mode="json") if before else None,
            },
        )
