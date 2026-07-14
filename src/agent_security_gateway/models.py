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
class DelegationScope:
    tools: list[str]
    actions: list[str]
    resources: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationScope":
        return cls(
            tools=list(data.get("tools", [])),
            actions=list(data.get("actions", [])),
            resources=list(data.get("resources", [])),
        )

    def allows(self, tool_name: str, action: str, resource: str | None = None) -> bool:
        if tool_name not in self.tools or action not in self.actions:
            return False
        if not self.resources or resource is None:
            return True
        return any(resource.startswith(allowed) for allowed in self.resources)

    def attenuates(self, parent: "DelegationScope") -> bool:
        return (
            set(self.tools).issubset(parent.tools)
            and set(self.actions).issubset(parent.actions)
            and set(self.resources).issubset(parent.resources)
        )


@dataclass(frozen=True)
class DelegationState:
    delegation_id: str
    agent_id: str
    root_principal: str
    scope: DelegationScope
    parent_agent_id: str | None = None
    parent_delegation_id: str | None = None
    approval_ref: str | None = None
    revocation_epoch: int = 0
    status: str = "active"
    issued_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationState":
        return cls(
            delegation_id=data["delegation_id"],
            agent_id=data["agent_id"],
            root_principal=data["root_principal"],
            scope=DelegationScope.from_dict(data["scope"]),
            parent_agent_id=data.get("parent_agent_id"),
            parent_delegation_id=data.get("parent_delegation_id"),
            approval_ref=data.get("approval_ref"),
            revocation_epoch=int(data.get("revocation_epoch", 0)),
            status=data.get("status", "active"),
            issued_at=data.get("issued_at")
            or datetime.now(timezone.utc).isoformat(),
            expires_at=data.get("expires_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DelegationEnvelope:
    delegation_id: str
    agent_id: str
    root_principal: str
    scope_ref: str
    revocation_epoch: int
    expires_at: str
    trace_id: str
    parent_agent_id: str | None = None
    approval_ref: str | None = None
    signature: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationEnvelope":
        return cls(
            delegation_id=data["delegation_id"],
            agent_id=data["agent_id"],
            root_principal=data["root_principal"],
            scope_ref=data["scope_ref"],
            revocation_epoch=int(data["revocation_epoch"]),
            expires_at=data["expires_at"],
            trace_id=data["trace_id"],
            parent_agent_id=data.get("parent_agent_id"),
            approval_ref=data.get("approval_ref"),
            signature=data.get("signature"),
        )

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        data = asdict(self)
        if not include_signature:
            data.pop("signature", None)
        return data


@dataclass(frozen=True)
class AgentRequest:
    agent_id: str
    role: str
    tool_name: str
    action: str
    arguments: dict[str, Any]
    user_intent: str
    provenance: Provenance
    delegation: DelegationEnvelope | None = None
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
            "delegation": DelegationEnvelope.from_dict(data["delegation"])
            if data.get("delegation")
            else None,
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
class ApprovalBinding:
    agent_id: str
    tool_name: str
    action: str
    resource: str | None = None
    delegation_id: str | None = None
    policy_version: str = "default"
    max_uses: int = 1
    uses: int = 0

    @classmethod
    def from_request(
        cls, request: AgentRequest, policy_version: str = "default"
    ) -> "ApprovalBinding":
        return cls(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            action=request.action,
            resource=request.arguments.get("path") or request.arguments.get("resource"),
            delegation_id=request.delegation.delegation_id if request.delegation else None,
            policy_version=policy_version,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApprovalBinding":
        return cls(
            agent_id=data["agent_id"],
            tool_name=data["tool_name"],
            action=data["action"],
            resource=data.get("resource"),
            delegation_id=data.get("delegation_id"),
            policy_version=data.get("policy_version", "default"),
            max_uses=int(data.get("max_uses", 1)),
            uses=int(data.get("uses", 0)),
        )

    def matches(self, request: AgentRequest, policy_version: str = "default") -> bool:
        candidate = ApprovalBinding.from_request(request, policy_version)
        return (
            self.agent_id == candidate.agent_id
            and self.tool_name == candidate.tool_name
            and self.action == candidate.action
            and self.resource == candidate.resource
            and self.delegation_id == candidate.delegation_id
            and self.policy_version == candidate.policy_version
        )


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
