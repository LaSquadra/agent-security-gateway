from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from .models import AgentRequest, GatewayDecision, TraceEvent


class JsonlTraceExporter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit_decision(self, request: AgentRequest, decision: GatewayDecision) -> None:
        root_span_id = str(uuid4())
        trace_id = _trace_id(request)
        events = [
            self._event(
                request,
                decision,
                trace_id,
                root_span_id,
                None,
                "request_received",
                "ok",
                0,
                {},
            ),
            self._event(
                request,
                decision,
                trace_id,
                str(uuid4()),
                root_span_id,
                "risk_scored",
                "ok",
                1,
                {
                    "security.risk_score": decision.risk_score,
                    "security.findings": [
                        finding.__dict__ for finding in decision.findings
                    ],
                },
            ),
            self._event(
                request,
                decision,
                trace_id,
                str(uuid4()),
                root_span_id,
                "policy_evaluated",
                "ok",
                1,
                {"security.reasons": decision.reasons},
            ),
            self._event(
                request,
                decision,
                trace_id,
                str(uuid4()),
                root_span_id,
                "decision_emitted",
                decision.decision.value,
                1,
                {
                    "security.decision": decision.decision.value,
                    "security.approval_id": decision.approval_id,
                },
            ),
        ]

        with self.path.open("a", encoding="utf-8") as trace_file:
            for event in events:
                trace_file.write(json.dumps(event.to_dict()) + "\n")

    def _event(
        self,
        request: AgentRequest,
        decision: GatewayDecision,
        trace_id: str,
        span_id: str,
        parent_span_id: str | None,
        event_type: str,
        status: str,
        duration_ms: int,
        extra_attributes: dict,
    ) -> TraceEvent:
        event = TraceEvent(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=f"agent_security_gateway.{event_type}",
            timestamp=request.timestamp,
            duration_ms=duration_ms,
            status=status,
            attributes={
                "request.id": request.request_id,
                "trace.id": trace_id,
                "agent.id": request.agent_id,
                "agent.role": request.role,
                "tool.name": request.tool_name,
                "tool.action": request.action,
                "policy.version": decision.policy_version,
                "approval.id": decision.approval_id,
                "provenance.source": request.provenance.source,
                "provenance.trust_level": request.provenance.trust_level,
                "provenance.taint_labels": request.provenance.taint_labels,
                **_delegation_attributes(request),
                **extra_attributes,
            },
        )
        return event


def _trace_id(request: AgentRequest) -> str:
    return request.delegation.trace_id if request.delegation else request.request_id


def _delegation_attributes(request: AgentRequest) -> dict:
    if not request.delegation:
        return {
            "delegation.id": None,
            "delegation.parent_agent_id": None,
            "delegation.root_principal": None,
            "delegation.revocation_epoch": None,
        }
    return {
        "delegation.id": request.delegation.delegation_id,
        "delegation.parent_agent_id": request.delegation.parent_agent_id,
        "delegation.root_principal": request.delegation.root_principal,
        "delegation.revocation_epoch": request.delegation.revocation_epoch,
    }
