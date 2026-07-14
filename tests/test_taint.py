import json
import tempfile
import unittest
from pathlib import Path

from agent_security_gateway import AgentRequest, AgentSecurityGateway, Decision
from agent_security_gateway.ledger import DecisionLedger
from agent_security_gateway.models import Provenance
from agent_security_gateway.taint import add_taint, request_with_taint
from agent_security_gateway.telemetry import JsonlTraceExporter


class TaintTrackingTests(unittest.TestCase):
    def test_tainted_sensitive_flow_blocks(self) -> None:
        request = AgentRequest(
            agent_id="support-agent-01",
            role="release_manager",
            tool_name="network",
            action="send_external",
            arguments={"destination": "https://example.invalid", "body": "summary"},
            user_intent="Send retrieved support context externally.",
            provenance=Provenance(
                source="uploaded_ticket_attachment",
                trust_level="user_upload",
                taint_labels=["prompt_injection"],
            ),
        )

        decision = AgentSecurityGateway().inspect(request)

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertGreaterEqual(decision.risk_score, 80)
        self.assertIn("tainted_sensitive_flow", [f.category for f in decision.findings])

    def test_taint_helpers_preserve_existing_labels_without_duplicates(self) -> None:
        provenance = Provenance(
            source="web",
            trust_level="web",
            taint_labels=["untrusted_code"],
        )
        request = AgentRequest(
            agent_id="agent-1",
            role="researcher",
            tool_name="filesystem",
            action="read_file",
            arguments={"path": "README.md"},
            user_intent="Read documentation.",
            provenance=provenance,
        )

        updated_provenance = add_taint(provenance, "untrusted_code", "secret")
        updated_request = request_with_taint(request, "secret")

        self.assertEqual(updated_provenance.taint_labels, ["untrusted_code", "secret"])
        self.assertEqual(updated_request.provenance.taint_labels, ["untrusted_code", "secret"])

    def test_trace_and_ledger_record_taint_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            trace_path = root / "traces.jsonl"
            ledger_path = root / "ledger.jsonl"
            gateway = AgentSecurityGateway(
                trace_exporter=JsonlTraceExporter(trace_path),
                decision_ledger=DecisionLedger(ledger_path),
            )
            request = AgentRequest(
                agent_id="support-agent-01",
                role="release_manager",
                tool_name="network",
                action="send_external",
                arguments={"destination": "https://example.invalid", "body": "summary"},
                user_intent="Send retrieved support context externally.",
                provenance=Provenance(
                    source="uploaded_ticket_attachment",
                    trust_level="user_upload",
                    taint_labels=["prompt_injection"],
                ),
            )

            gateway.inspect(request)
            trace_event = json.loads(trace_path.read_text(encoding="utf-8").splitlines()[0])
            ledger_entry = json.loads(ledger_path.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(
            trace_event["attributes"]["provenance.taint_labels"],
            ["prompt_injection"],
        )
        self.assertEqual(
            ledger_entry["provenance_taint_labels"],
            ["prompt_injection"],
        )


if __name__ == "__main__":
    unittest.main()
