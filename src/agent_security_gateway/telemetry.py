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
        event = TraceEvent(
            trace_id=request.request_id,
            span_id=str(uuid4()),
            name="agent_security_gateway.decision",
            timestamp=request.timestamp,
            attributes={
                "agent.id": request.agent_id,
                "agent.role": request.role,
                "tool.name": request.tool_name,
                "tool.action": request.action,
                "security.decision": decision.decision.value,
                "security.risk_score": decision.risk_score,
                "security.reasons": decision.reasons,
                "security.approval_id": decision.approval_id,
                "provenance.source": request.provenance.source,
                "provenance.trust_level": request.provenance.trust_level,
            },
        )

        with self.path.open("a", encoding="utf-8") as trace_file:
            trace_file.write(json.dumps(event.to_dict()) + "\n")
