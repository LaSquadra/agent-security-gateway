import json
import tempfile
import unittest
from pathlib import Path

from agent_security_gateway import AgentSecurityGateway
from agent_security_gateway.authz_state import AuthorizationStateStore
from agent_security_gateway.envelopes import EnvelopeSigner
from agent_security_gateway.ledger import DecisionLedger
from agent_security_gateway.mcp_adapter import McpGatewayAdapter, McpToolCall
from agent_security_gateway.models import (
    DelegationEnvelope,
    DelegationScope,
    DelegationState,
    Provenance,
)
from agent_security_gateway.telemetry import JsonlTraceExporter


class McpGatewayAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.store = AuthorizationStateStore(root / "delegations")
        self.signer = EnvelopeSigner("test-secret")
        self.ledger_path = root / "ledger" / "decisions.jsonl"
        self.trace_path = root / "traces" / "events.jsonl"
        self.gateway = AgentSecurityGateway(
            authz_store=self.store,
            envelope_signer=self.signer,
            decision_ledger=DecisionLedger(self.ledger_path),
            trace_exporter=JsonlTraceExporter(self.trace_path),
        )
        self.executions: list[dict] = []
        self.adapter = McpGatewayAdapter(
            self.gateway,
            tools={"filesystem.read_file": self._read_file},
        )
        self.store.create(
            DelegationState(
                delegation_id="dlg-mcp-read",
                agent_id="agent-child-1",
                root_principal="user:ryan",
                scope=DelegationScope(
                    tools=["filesystem"],
                    actions=["read_file"],
                    resources=["README"],
                ),
                parent_agent_id="agent-root-1",
                expires_at="2099-01-01T00:00:00Z",
            )
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_allowed_mcp_call_executes_tool_and_writes_ledger_context(self) -> None:
        result = self.adapter.handle_tool_call(self._call())
        entries = [
            json.loads(line)
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines()
        ]

        self.assertTrue(result.executed)
        self.assertEqual(result.result, {"content": "fake README"})
        self.assertEqual(len(self.executions), 1)
        self.assertEqual(entries[0]["request_id"], "mcp-call-1")
        self.assertEqual(entries[0]["trace_id"], "trace-mcp-1")
        self.assertEqual(entries[0]["parent_agent_id"], "agent-root-1")
        self.assertEqual(entries[0]["policy_version"], "default-v1")

    def test_mcp_trace_and_ledger_share_attribution_context(self) -> None:
        self.adapter.handle_tool_call(self._call())
        ledger_entry = json.loads(
            self.ledger_path.read_text(encoding="utf-8").splitlines()[0]
        )
        trace_events = [
            json.loads(line)
            for line in self.trace_path.read_text(encoding="utf-8").splitlines()
        ]
        decision_event = trace_events[-1]
        attrs = decision_event["attributes"]

        self.assertEqual(decision_event["trace_id"], ledger_entry["trace_id"])
        self.assertEqual(attrs["request.id"], ledger_entry["request_id"])
        self.assertEqual(attrs["trace.id"], ledger_entry["trace_id"])
        self.assertEqual(attrs["delegation.id"], ledger_entry["delegation_id"])
        self.assertEqual(
            attrs["delegation.parent_agent_id"], ledger_entry["parent_agent_id"]
        )
        self.assertEqual(
            attrs["delegation.root_principal"], ledger_entry["root_principal"]
        )
        self.assertEqual(attrs["policy.version"], ledger_entry["policy_version"])

    def test_blocked_mcp_call_does_not_execute_tool(self) -> None:
        call = self._call(action="write_file")

        result = self.adapter.handle_tool_call(call)

        self.assertFalse(result.executed)
        self.assertEqual(self.executions, [])
        self.assertEqual(result.decision["decision"], "block")

    def test_missing_tool_handler_does_not_execute_but_preserves_allow_decision(self) -> None:
        call = self._call(tool_name="filesystem", action="read_file")
        adapter = McpGatewayAdapter(self.gateway, tools={})

        result = adapter.handle_tool_call(call)

        self.assertFalse(result.executed)
        self.assertIn("No handler registered", result.error or "")
        self.assertEqual(result.decision["decision"], "allow")

    def _read_file(self, arguments: dict) -> dict:
        self.executions.append(arguments)
        return {"content": "fake README"}

    def _call(
        self,
        tool_name: str = "filesystem",
        action: str = "read_file",
    ) -> McpToolCall:
        return McpToolCall(
            call_id="mcp-call-1",
            agent_id="agent-child-1",
            role="researcher",
            tool_name=tool_name,
            action=action,
            arguments={"path": "README.md"},
            user_intent="Read documentation through MCP.",
            provenance=Provenance(source="parent-agent", trust_level="trusted"),
            delegation=self.signer.sign(
                DelegationEnvelope(
                    delegation_id="dlg-mcp-read",
                    agent_id="agent-child-1",
                    parent_agent_id="agent-root-1",
                    root_principal="user:ryan",
                    scope_ref="scope-read-readme",
                    revocation_epoch=0,
                    expires_at="2099-01-01T00:00:00Z",
                    trace_id="trace-mcp-1",
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()
