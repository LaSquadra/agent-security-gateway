import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agent_security_gateway.showcase import run_showcase


class ShowcaseTests(unittest.TestCase):
    def test_showcase_runs_story_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "showcase"
            with redirect_stdout(StringIO()) as buffer:
                results = run_showcase(output_dir)
            output = buffer.getvalue()

            scenario_names = [result.scenario for result in results]

            self.assertIn("Agent Security Gateway showcase", output)
            self.assertIn("Low-risk read", scenario_names)
            self.assertIn("Prompt injection image", scenario_names)
            self.assertIn("Tainted external send", scenario_names)
            self.assertIn("Production deploy", scenario_names)
            self.assertIn("Approved deploy", scenario_names)
            self.assertIn("Approval replay", scenario_names)
            self.assertIn("MCP delegated read", scenario_names)
            self.assertIn("OTLP span export", scenario_names)
            self.assertTrue((output_dir / "decisions.jsonl").exists())
            self.assertTrue((output_dir / "otlp-traces.json").exists())


if __name__ == "__main__":
    unittest.main()
