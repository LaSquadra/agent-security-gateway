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
        events = [
            self._event(request, root_span_id, None, "request_received", "ok", 0, {}),
            self._event(
                request,
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
                str(uuid4()),
                root_span_id,
                "policy_evaluated",
                "ok",
                1,
                {"security.reasons": decision.reasons},
            ),
            self._event(
                request,
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
        span_id: str,
        parent_span_id: str | None,
        event_type: str,
        status: str,
        duration_ms: int,
        extra_attributes: dict,
    ) -> TraceEvent:
        event = TraceEvent(
            trace_id=request.request_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=f"agent_security_gateway.{event_type}",
            timestamp=request.timestamp,
            duration_ms=duration_ms,
            status=status,
            attributes={
                "agent.id": request.agent_id,
                "agent.role": request.role,
                "tool.name": request.tool_name,
                "tool.action": request.action,
                "provenance.source": request.provenance.source,
                "provenance.trust_level": request.provenance.trust_level,
                **extra_attributes,
            },
        )
        return event
