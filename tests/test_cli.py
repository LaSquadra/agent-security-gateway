import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agent_security_gateway.cli import main


class CliTests(unittest.TestCase):
    def test_validate_policy_command(self) -> None:
        result = _run_cli(["validate-policy", "config/default_policy.json"])

        self.assertEqual(result, 0)

    def test_showcase_command_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_cli(["showcase", "--output-dir", temp_dir])

        self.assertEqual(result, 0)

    def test_inspect_command_writes_trace_and_approval_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "trace.jsonl"
            approval_dir = Path(temp_dir) / "approvals"

            result = _run_cli(
                [
                    "inspect",
                    "examples/production_deploy.json",
                    "--policy",
                    "config/default_policy.json",
                    "--trace-path",
                    str(trace_path),
                    "--approval-dir",
                    str(approval_dir),
                ]
            )

            approvals = list(approval_dir.glob("approval-*.json"))
            trace_exists = trace_path.exists()

        self.assertEqual(result, 0)
        self.assertTrue(trace_exists)
        self.assertEqual(len(approvals), 1)

    def test_inspect_command_can_write_otlp_json_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "trace-otlp.json"
            result = _run_cli(
                [
                    "inspect",
                    "examples/low_risk_read.json",
                    "--policy",
                    "config/default_policy.json",
                    "--trace-path",
                    str(trace_path),
                    "--trace-format",
                    "otlp-json",
                    "--ledger-path",
                    str(Path(temp_dir) / "ledger.jsonl"),
                ]
            )
            payload = json.loads(trace_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertIn("resourceSpans", payload)

    def test_resolve_approval_command_updates_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            approval_dir = Path(temp_dir) / "approvals"
            trace_path = Path(temp_dir) / "trace.jsonl"
            _run_cli(
                [
                    "inspect",
                    "examples/production_deploy.json",
                    "--policy",
                    "config/default_policy.json",
                    "--trace-path",
                    str(trace_path),
                    "--approval-dir",
                    str(approval_dir),
                ]
            )
            approval_path = next(approval_dir.glob("approval-*.json"))
            approval_id = approval_path.stem

            result = _run_cli(
                [
                    "resolve-approval",
                    approval_id,
                    "approved",
                    "--actor",
                    "test-reviewer",
                    "--approval-dir",
                    str(approval_dir),
                ]
            )
            record = json.loads(approval_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(record["status"], "approved")


def _run_cli(args: list[str]) -> int:
    with redirect_stdout(StringIO()):
        return main(args)


if __name__ == "__main__":
    unittest.main()
