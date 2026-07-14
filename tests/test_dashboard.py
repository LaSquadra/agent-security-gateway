import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agent_security_gateway.cli import main
from agent_security_gateway.dashboard import build_dashboard
from agent_security_gateway.showcase import run_showcase


class DashboardTests(unittest.TestCase):
    def test_build_dashboard_from_showcase_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir) / "showcase"
            run_showcase(artifact_dir)

            dashboard = build_dashboard(artifact_dir)
            content = dashboard.read_text(encoding="utf-8")

        self.assertIn("Agent Security Gateway Dashboard", content)
        self.assertIn("Decision Ledger", content)
        self.assertIn("Approval Records", content)
        self.assertIn("Tainted Flows", content)
        self.assertIn("showcase-mcp-read", content)

    def test_dashboard_command_writes_html(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir) / "showcase"
            output = Path(temp_dir) / "dashboard.html"
            run_showcase(artifact_dir)

            with redirect_stdout(StringIO()) as stdout:
                result = main(
                    [
                        "dashboard",
                        "--artifact-dir",
                        str(artifact_dir),
                        "--output",
                        str(output),
                    ]
                )

            output_exists = output.exists()

        self.assertEqual(result, 0)
        self.assertTrue(output_exists)
        self.assertIn("Dashboard written", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
