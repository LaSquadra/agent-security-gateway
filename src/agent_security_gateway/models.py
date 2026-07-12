from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Provenance:
    source: str
    trust_level: str = "unknown"
    retrieved_from: str | None = None
    session_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Provenance":
        return cls(
            source=data["source"],
            trust_level=data.get("trust_level", "unknown"),
            retrieved_from=data.get("retrieved_from"),
            session_id=data.get("session_id"),
        )


@dataclass(frozen=True)
class AgentRequest:
    agent_id: str
    role: str
    tool_name: str
    action: str
    arguments: dict[str, Any]
    user_intent: str
    provenance: Provenance
    request_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentRequest":
        request_args = {
            "agent_id": data["agent_id"],
            "role": data["role"],
            "tool_name": data["tool_name"],
            "action": data["action"],
            "arguments": data.get("arguments", {}),
            "user_intent": data["user_intent"],
            "provenance": Provenance.from_dict(data["provenance"]),
        }
        if "request_id" in data:
            request_args["request_id"] = data["request_id"]
        if "timestamp" in data:
            request_args["timestamp"] = data["timestamp"]
        return cls(**request_args)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskFinding:
    category: str
    score: int
    detail: str


@dataclass(frozen=True)
class GatewayDecision:
    request_id: str
    decision: Decision
    risk_score: int
    reasons: list[str]
    findings: list[RiskFinding]
    approval_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        return data


@dataclass(frozen=True)
class TraceEvent:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    timestamp: str
    duration_ms: int
    status: str
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
