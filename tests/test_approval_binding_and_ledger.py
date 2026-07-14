import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from agent_security_gateway import AgentRequest, AgentSecurityGateway, Decision
from agent_security_gateway.approvals import ApprovalStore
from agent_security_gateway.authz_state import AuthorizationStateStore
from agent_security_gateway.envelopes import EnvelopeSigner
from agent_security_gateway.ledger import DecisionLedger
from agent_security_gateway.models import (
    DelegationEnvelope,
    DelegationScope,
    DelegationState,
    Provenance,
)


class ApprovalBindingAndLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.approval_store = ApprovalStore(root / "approvals")
        self.authz_store = AuthorizationStateStore(root / "delegations")
        self.signer = EnvelopeSigner("test-secret")
        self.ledger_path = root / "ledger" / "decisions.jsonl"
        self.gateway = AgentSecurityGateway(
            approval_store=self.approval_store,
            authz_store=self.authz_store,
            envelope_signer=self.signer,
            decision_ledger=DecisionLedger(self.ledger_path),
        )
        self.authz_store.create(
            DelegationState(
                delegation_id="dlg-release",
                agent_id="release-agent-1",
                root_principal="user:ryan",
                scope=DelegationScope(
                    tools=["deployment", "network"],
                    actions=["deploy", "send_external"],
                ),
                revocation_epoch=0,
                expires_at="2099-01-01T00:00:00Z",
            )
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_approved_binding_allows_exact_action_once(self) -> None:
        pending = self.gateway.inspect(self._deploy_request())
        self.assertEqual(pending.decision, Decision.REQUIRE_APPROVAL)
        assert pending.approval_id is not None

        self.approval_store.resolve(pending.approval_id, "approved", "reviewer")

        approved = self.gateway.inspect(self._deploy_request(pending.approval_id))
        replay = self.gateway.inspect(self._deploy_request(pending.approval_id))

        self.assertEqual(approved.decision, Decision.ALLOW)
        self.assertEqual(approved.approval_id, pending.approval_id)
        self.assertEqual(replay.decision, Decision.BLOCK)
        self.assertIn("already been used", " ".join(replay.reasons))

    def test_approval_binding_rejects_different_action(self) -> None:
        pending = self.gateway.inspect(self._deploy_request())
        assert pending.approval_id is not None
        self.approval_store.resolve(pending.approval_id, "approved", "reviewer")

        decision = self.gateway.inspect(self._send_external_request(pending.approval_id))

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertIn("does not match", " ".join(decision.reasons))

    def test_decision_ledger_records_security_context(self) -> None:
        decision = self.gateway.inspect(self._deploy_request())
        entries = [
            json.loads(line)
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines()
        ]

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["request_id"], decision.request_id)
        self.assertEqual(entries[0]["delegation_id"], "dlg-release")
        self.assertEqual(entries[0]["root_principal"], "user:ryan")
        self.assertEqual(entries[0]["decision"], "require_approval")
        self.assertEqual(entries[0]["tool_name"], "deployment")

    def _deploy_request(self, approval_ref: str | None = None) -> AgentRequest:
        return AgentRequest(
            agent_id="release-agent-1",
            role="release_manager",
            tool_name="deployment",
            action="deploy",
            arguments={"environment": "production"},
            user_intent="Deploy the reviewed service to production.",
            provenance=Provenance(source="ticket", trust_level="trusted"),
            delegation=self._envelope(approval_ref),
        )

    def _send_external_request(self, approval_ref: str | None = None) -> AgentRequest:
        return AgentRequest(
            agent_id="release-agent-1",
            role="release_manager",
            tool_name="network",
            action="send_external",
            arguments={"resource": "https://example.invalid", "body": "status only"},
            user_intent="Send deployment status to an external endpoint.",
            provenance=Provenance(source="ticket", trust_level="trusted"),
            delegation=self._envelope(approval_ref),
        )

    def _envelope(self, approval_ref: str | None = None) -> DelegationEnvelope:
        envelope = DelegationEnvelope(
            delegation_id="dlg-release",
            agent_id="release-agent-1",
            root_principal="user:ryan",
            scope_ref="scope-release",
            revocation_epoch=0,
            expires_at="2099-01-01T00:00:00Z",
            trace_id="trace-release",
        )
        if approval_ref:
            envelope = replace(envelope, approval_ref=approval_ref)
        return self.signer.sign(envelope)


if __name__ == "__main__":
    unittest.main()
