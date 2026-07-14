from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from .gateway import AgentSecurityGateway
from .models import AgentRequest, Decision, DelegationEnvelope, Provenance

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class McpToolCall:
    call_id: str
    agent_id: str
    role: str
    tool_name: str
    action: str
    arguments: dict[str, Any]
    user_intent: str
    provenance: Provenance
    delegation: DelegationEnvelope | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "McpToolCall":
        return cls(
            call_id=data["call_id"],
            agent_id=data["agent_id"],
            role=data["role"],
            tool_name=data["tool_name"],
            action=data["action"],
            arguments=data.get("arguments", {}),
            user_intent=data["user_intent"],
            provenance=Provenance.from_dict(data["provenance"]),
            delegation=DelegationEnvelope.from_dict(data["delegation"])
            if data.get("delegation")
            else None,
        )

    def to_agent_request(self) -> AgentRequest:
        return AgentRequest(
            agent_id=self.agent_id,
            role=self.role,
            tool_name=self.tool_name,
            action=self.action,
            arguments=self.arguments,
            user_intent=self.user_intent,
            provenance=self.provenance,
            delegation=self.delegation,
            request_id=self.call_id,
        )


@dataclass(frozen=True)
class McpToolResult:
    call_id: str
    executed: bool
    decision: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class McpGatewayAdapter:
    def __init__(
        self,
        gateway: AgentSecurityGateway,
        tools: dict[str, ToolHandler] | None = None,
    ) -> None:
        self.gateway = gateway
        self.tools = tools or {}

    def handle_tool_call(self, call: McpToolCall) -> McpToolResult:
        request = call.to_agent_request()
        decision = self.gateway.inspect(request)

        if decision.decision != Decision.ALLOW:
            return McpToolResult(
                call_id=call.call_id,
                executed=False,
                decision=decision.to_dict(),
                error=f"Gateway decision was {decision.decision.value}.",
            )

        tool_key = self._tool_key(call.tool_name, call.action)
        handler = self.tools.get(tool_key)
        if not handler:
            return McpToolResult(
                call_id=call.call_id,
                executed=False,
                decision=decision.to_dict(),
                error=f"No handler registered for {tool_key}.",
            )

        return McpToolResult(
            call_id=call.call_id,
            executed=True,
            decision=decision.to_dict(),
            result=handler(call.arguments),
        )

    @staticmethod
    def _tool_key(tool_name: str, action: str) -> str:
        return f"{tool_name}.{action}"
