from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AgentRequest, GatewayDecision


@dataclass(frozen=True)
class DecisionLedgerEntry:
    request_id: str
    trace_id: str | None
    timestamp: str
    agent_id: str
    parent_agent_id: str | None
    root_principal: str | None
    delegation_id: str | None
    revocation_epoch: int | None
    approval_id: str | None
    tool_name: str
    action: str
    resource: str | None
    decision: str
    risk_score: int
    reasons: list[str]
    risk_findings: list[dict[str, Any]] = field(default_factory=list)


class DecisionLedger:
    def __init__(self, path: str | Path = "ledger/decisions.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, request: AgentRequest, decision: GatewayDecision) -> None:
        delegation = request.delegation
        entry = DecisionLedgerEntry(
            request_id=request.request_id,
            trace_id=delegation.trace_id if delegation else request.request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=request.agent_id,
            parent_agent_id=delegation.parent_agent_id if delegation else None,
            root_principal=delegation.root_principal if delegation else None,
            delegation_id=delegation.delegation_id if delegation else None,
            revocation_epoch=delegation.revocation_epoch if delegation else None,
            approval_id=decision.approval_id,
            tool_name=request.tool_name,
            action=request.action,
            resource=request.arguments.get("path") or request.arguments.get("resource"),
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            reasons=decision.reasons,
            risk_findings=[asdict(finding) for finding in decision.findings],
        )
        with self.path.open("a", encoding="utf-8") as ledger_file:
            ledger_file.write(json.dumps(asdict(entry)) + "\n")
