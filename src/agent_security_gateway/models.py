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


@dataclass(frozen=True)
class TraceEvent:
    trace_id: str
    span_id: str
    name: str
    timestamp: str
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
