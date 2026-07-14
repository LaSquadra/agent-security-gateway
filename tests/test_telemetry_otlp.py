import json
import tempfile
import unittest
from pathlib import Path

from agent_security_gateway import AgentRequest, AgentSecurityGateway
from agent_security_gateway.models import Provenance
from agent_security_gateway.telemetry import OtlpJsonTraceExporter


class OtlpTelemetryTests(unittest.TestCase):
    def test_otlp_exporter_writes_resource_spans_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "otlp.json"
            gateway = AgentSecurityGateway(
                trace_exporter=OtlpJsonTraceExporter(trace_path)
            )
            gateway.inspect(
                AgentRequest(
                    agent_id="agent-1",
                    role="researcher",
                    tool_name="filesystem",
                    action="read_file",
                    arguments={"path": "README.md"},
                    user_intent="Read documentation.",
                    provenance=Provenance(source="user", trust_level="trusted"),
                )
            )
            payload = json.loads(trace_path.read_text(encoding="utf-8"))

        resource_span = payload["resourceSpans"][0]
        scope_span = resource_span["scopeSpans"][0]
        spans = scope_span["spans"]
        first_span = spans[0]
        first_attributes = {
            item["key"]: item["value"] for item in first_span["attributes"]
        }

        self.assertEqual(len(spans), 4)
        self.assertEqual(
            resource_span["resource"]["attributes"][0]["key"],
            "service.name",
        )
        self.assertIn("traceId", first_span)
        self.assertIn("spanId", first_span)
        self.assertIn("startTimeUnixNano", first_span)
        self.assertIn("endTimeUnixNano", first_span)
        self.assertEqual(
            first_attributes["policy.version"]["stringValue"],
            "default-v1",
        )
        self.assertEqual(
            first_attributes["request.id"]["stringValue"],
            first_attributes["trace.id"]["stringValue"],
        )


if __name__ == "__main__":
    unittest.main()
