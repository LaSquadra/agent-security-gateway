from __future__ import annotations

from uuid import uuid4

from .approvals import ApprovalStore
from .models import AgentRequest, Decision, GatewayDecision
from .policy import GatewayPolicy
from .risk import score_request
from .telemetry import JsonlTraceExporter


class AgentSecurityGateway:
    def __init__(
        self,
        policy: GatewayPolicy | None = None,
        trace_exporter: JsonlTraceExporter | None = None,
        approval_store: ApprovalStore | None = None,
    ) -> None:
        self.policy = policy or GatewayPolicy.default()
        self.trace_exporter = trace_exporter
        self.approval_store = approval_store

    def inspect(self, request: AgentRequest) -> GatewayDecision:
        permission_decision, permission_reasons = self.policy.evaluate_permissions(
            request
        )
        risk_score, findings = score_request(request)
        risk_decision, risk_reasons = self.policy.evaluate_risk(risk_score)

        final_decision = self._combine(permission_decision, risk_decision)
        reasons = permission_reasons + risk_reasons
        approval_id = (
            f"approval-{uuid4()}" if final_decision == Decision.REQUIRE_APPROVAL else None
        )

        gateway_decision = GatewayDecision(
            request_id=request.request_id,
            decision=final_decision,
            risk_score=risk_score,
            reasons=reasons,
            findings=findings,
            approval_id=approval_id,
        )

        if self.trace_exporter:
            self.trace_exporter.emit_decision(request, gateway_decision)

        if self.approval_store and gateway_decision.approval_id:
            self.approval_store.create(request, gateway_decision)

        return gateway_decision

    @staticmethod
    def _combine(permission_decision: Decision, risk_decision: Decision) -> Decision:
        if Decision.BLOCK in {permission_decision, risk_decision}:
            return Decision.BLOCK
        if Decision.REQUIRE_APPROVAL in {permission_decision, risk_decision}:
            return Decision.REQUIRE_APPROVAL
        return Decision.ALLOW
