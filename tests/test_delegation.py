import tempfile
import unittest
from dataclasses import replace

from agent_security_gateway import AgentRequest, AgentSecurityGateway, Decision
from agent_security_gateway.authz_state import AuthorizationStateStore
from agent_security_gateway.envelopes import EnvelopeSigner
from agent_security_gateway.models import (
    DelegationEnvelope,
    DelegationScope,
    DelegationState,
    Provenance,
)


class DelegationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = AuthorizationStateStore(self.temp_dir.name)
        self.signer = EnvelopeSigner("test-secret")
        self.gateway = AgentSecurityGateway(
            authz_store=self.store,
            envelope_signer=self.signer,
        )
        self.state = DelegationState(
            delegation_id="dlg-1",
            agent_id="agent-child-1",
            root_principal="user:ryan",
            scope=DelegationScope(
                tools=["filesystem"],
                actions=["read_file"],
                resources=["README"],
            ),
            parent_agent_id="agent-root-1",
            revocation_epoch=0,
            expires_at="2099-01-01T00:00:00Z",
        )
        self.store.create(self.state)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_allows_valid_delegated_request(self) -> None:
        decision = self.gateway.inspect(self._request())

        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIn("Delegation envelope and scope validated.", decision.reasons)

    def test_blocks_invalid_envelope_signature(self) -> None:
        signed = self._envelope()
        bad_envelope = replace(signed, agent_id="different-agent")

        decision = self.gateway.inspect(self._request(bad_envelope))

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertIn("signature is invalid", " ".join(decision.reasons))

    def test_blocks_stale_revocation_epoch(self) -> None:
        request = self._request()
        self.store.revoke("dlg-1")

        decision = self.gateway.inspect(request)

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertIn("revoked", " ".join(decision.reasons))

    def test_rejects_child_scope_that_exceeds_parent(self) -> None:
        with self.assertRaises(ValueError):
            self.store.create_child(
                delegation_id="dlg-child-bad",
                agent_id="agent-child-2",
                parent_delegation_id="dlg-1",
                scope=DelegationScope(
                    tools=["filesystem"],
                    actions=["read_file", "write_file"],
                    resources=["README"],
                ),
            )

    def test_blocks_request_outside_delegated_scope(self) -> None:
        request = AgentRequest(
            agent_id="agent-child-1",
            role="developer",
            tool_name="filesystem",
            action="write_file",
            arguments={"path": "README.md"},
            user_intent="Write project docs.",
            provenance=Provenance(source="parent-agent", trust_level="trusted"),
            delegation=self._envelope(),
        )

        decision = self.gateway.inspect(request)

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertIn("outside delegated scope", " ".join(decision.reasons))

    def test_blocks_missing_delegation_state(self) -> None:
        envelope = self.signer.sign(
            DelegationEnvelope(
                delegation_id="dlg-missing",
                agent_id="agent-child-1",
                parent_agent_id="agent-root-1",
                root_principal="user:ryan",
                scope_ref="scope-read-readme",
                revocation_epoch=0,
                expires_at="2099-01-01T00:00:00Z",
                trace_id="trace-1",
            )
        )

        decision = self.gateway.inspect(self._request(envelope))

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertIn("state was not found", " ".join(decision.reasons))

    def test_blocks_expired_delegation_state_even_with_valid_envelope(self) -> None:
        expired_state = DelegationState(
            delegation_id="dlg-expired-state",
            agent_id="agent-child-1",
            root_principal="user:ryan",
            scope=DelegationScope(
                tools=["filesystem"],
                actions=["read_file"],
                resources=["README"],
            ),
            revocation_epoch=0,
            expires_at="2000-01-01T00:00:00Z",
        )
        self.store.create(expired_state)
        envelope = self.signer.sign(
            DelegationEnvelope(
                delegation_id="dlg-expired-state",
                agent_id="agent-child-1",
                root_principal="user:ryan",
                scope_ref="scope-read-readme",
                revocation_epoch=0,
                expires_at="2099-01-01T00:00:00Z",
                trace_id="trace-1",
            )
        )

        decision = self.gateway.inspect(self._request(envelope))

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertIn("state is expired", " ".join(decision.reasons))

    def test_parent_without_resource_constraints_allows_child_resource_subset(self) -> None:
        parent = DelegationState(
            delegation_id="dlg-parent-wildcard",
            agent_id="agent-parent",
            root_principal="user:ryan",
            scope=DelegationScope(
                tools=["filesystem"],
                actions=["read_file"],
            ),
            expires_at="2099-01-01T00:00:00Z",
        )
        self.store.create(parent)

        child = self.store.create_child(
            delegation_id="dlg-child-narrow",
            agent_id="agent-child-2",
            parent_delegation_id="dlg-parent-wildcard",
            scope=DelegationScope(
                tools=["filesystem"],
                actions=["read_file"],
                resources=["README"],
            ),
        )

        self.assertEqual(child.parent_delegation_id, "dlg-parent-wildcard")

    def _request(self, envelope: DelegationEnvelope | None = None) -> AgentRequest:
        return AgentRequest(
            agent_id="agent-child-1",
            role="researcher",
            tool_name="filesystem",
            action="read_file",
            arguments={"path": "README.md"},
            user_intent="Read project documentation.",
            provenance=Provenance(source="parent-agent", trust_level="trusted"),
            delegation=envelope or self._envelope(),
        )

    def _envelope(self) -> DelegationEnvelope:
        return self.signer.sign(
            DelegationEnvelope(
                delegation_id="dlg-1",
                agent_id="agent-child-1",
                parent_agent_id="agent-root-1",
                root_principal="user:ryan",
                scope_ref="scope-read-readme",
                revocation_epoch=0,
                expires_at="2099-01-01T00:00:00Z",
                trace_id="trace-1",
            )
        )


if __name__ == "__main__":
    unittest.main()
