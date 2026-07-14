from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .approvals import ApprovalStore
from .authz_state import AuthorizationStateStore
from .envelopes import EnvelopeSigner, envelope_is_expired, parse_utc
from .ledger import DecisionLedger
from .models import AgentRequest, Decision, GatewayDecision, request_resource
from .policy import GatewayPolicy
from .risk import score_request
from .telemetry import JsonlTraceExporter


class AgentSecurityGateway:
    def __init__(
        self,
        policy: GatewayPolicy | None = None,
        trace_exporter: JsonlTraceExporter | None = None,
        approval_store: ApprovalStore | None = None,
        authz_store: AuthorizationStateStore | None = None,
        envelope_signer: EnvelopeSigner | None = None,
        decision_ledger: DecisionLedger | None = None,
    ) -> None:
        self.policy = policy or GatewayPolicy.default()
        self.trace_exporter = trace_exporter
        self.approval_store = approval_store
        self.authz_store = authz_store
        self.envelope_signer = envelope_signer
        self.decision_ledger = decision_ledger

    def inspect(self, request: AgentRequest) -> GatewayDecision:
        delegation_decision, delegation_reasons = self._evaluate_delegation(request)
        permission_decision, permission_reasons = self.policy.evaluate_permissions(
            request
        )
        risk_score, findings = score_request(request)
        risk_decision, risk_reasons = self.policy.evaluate_risk(risk_score)

        final_decision = self._combine(
            delegation_decision, permission_decision, risk_decision
        )
        reasons = delegation_reasons + permission_reasons + risk_reasons
        approval_ref = (
            request.delegation.approval_ref
            if request.delegation and request.delegation.approval_ref
            else request.arguments.get("approval_ref")
        )
        consumed_approval_id = None

        if (
            final_decision == Decision.REQUIRE_APPROVAL
            and approval_ref
            and self.approval_store
        ):
            approval_ok, approval_reason = self.approval_store.validate_and_consume(
                approval_ref, request, self.policy.policy_version
            )
            reasons.append(approval_reason)
            final_decision = Decision.ALLOW if approval_ok else Decision.BLOCK
            consumed_approval_id = approval_ref if approval_ok else None

        approval_id = (
            f"approval-{uuid4()}" if final_decision == Decision.REQUIRE_APPROVAL else None
        )

        gateway_decision = GatewayDecision(
            request_id=request.request_id,
            decision=final_decision,
            risk_score=risk_score,
            reasons=reasons,
            findings=findings,
            approval_id=approval_id or consumed_approval_id,
            policy_version=self.policy.policy_version,
        )

        if self.trace_exporter:
            self.trace_exporter.emit_decision(request, gateway_decision)

        if (
            self.approval_store
            and gateway_decision.approval_id
            and gateway_decision.decision == Decision.REQUIRE_APPROVAL
        ):
            self.approval_store.create(request, gateway_decision)

        if self.decision_ledger:
            self.decision_ledger.append(request, gateway_decision)

        return gateway_decision

    @staticmethod
    def _combine(*decisions: Decision) -> Decision:
        if Decision.BLOCK in decisions:
            return Decision.BLOCK
        if Decision.REQUIRE_APPROVAL in decisions:
            return Decision.REQUIRE_APPROVAL
        return Decision.ALLOW

    def _evaluate_delegation(self, request: AgentRequest) -> tuple[Decision, list[str]]:
        if not request.delegation:
            return Decision.ALLOW, ["No delegation envelope supplied."]
        if not self.authz_store or not self.envelope_signer:
            return (
                Decision.BLOCK,
                ["Delegation envelope supplied, but delegation validation is not configured."],
            )
        if not self.envelope_signer.verify(request.delegation):
            return Decision.BLOCK, ["Delegation envelope signature is invalid."]
        if envelope_is_expired(request.delegation):
            return Decision.BLOCK, ["Delegation envelope is expired."]

        try:
            state = self.authz_store.load(request.delegation.delegation_id)
        except FileNotFoundError:
            return Decision.BLOCK, ["Delegation state was not found."]

        if state.status != "active":
            return Decision.BLOCK, [f"Delegation status is '{state.status}'."]
        if state.expires_at and parse_utc(state.expires_at) <= datetime.now(timezone.utc):
            return Decision.BLOCK, ["Delegation state is expired."]
        if state.agent_id != request.delegation.agent_id:
            return Decision.BLOCK, ["Delegation agent does not match envelope agent."]
        if request.agent_id != request.delegation.agent_id:
            return Decision.BLOCK, ["Request agent does not match envelope agent."]
        if state.root_principal != request.delegation.root_principal:
            return Decision.BLOCK, ["Root principal does not match delegation state."]
        if state.revocation_epoch != request.delegation.revocation_epoch:
            return Decision.BLOCK, ["Delegation revocation epoch is stale."]

        resource = request_resource(request.arguments)
        if not state.scope.allows(request.tool_name, request.action, resource):
            return Decision.BLOCK, ["Requested tool/action is outside delegated scope."]

        return Decision.ALLOW, ["Delegation envelope and scope validated."]
