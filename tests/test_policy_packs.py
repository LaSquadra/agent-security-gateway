import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agent_security_gateway.cli import main
from agent_security_gateway.policy_packs import list_policy_packs, load_policy_pack


class PolicyPackTests(unittest.TestCase):
    def test_bundled_policy_packs_load_and_validate(self) -> None:
        packs = list_policy_packs()

        self.assertGreaterEqual(len(packs), 3)
        for pack in packs:
            policy = load_policy_pack(pack.stem)
            self.assertFalse(policy.validate(), pack.name)

    def test_policy_pack_command_lists_packs(self) -> None:
        with redirect_stdout(StringIO()) as output:
            result = main(["policy-packs"])

        self.assertEqual(result, 0)
        self.assertIn("appsec", output.getvalue())
        self.assertIn("soc", output.getvalue())
        self.assertIn("software_engineering", output.getvalue())

    def test_inspect_can_use_named_policy_pack(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with redirect_stdout(StringIO()) as output:
                result = main(
                    [
                        "inspect",
                        "examples/low_risk_read.json",
                        "--policy-pack",
                        "software_engineering",
                        "--trace-path",
                        str(Path(temp_dir) / "trace.jsonl"),
                        "--ledger-path",
                        str(Path(temp_dir) / "ledger.jsonl"),
                    ]
                )

        self.assertEqual(result, 0)
        self.assertIn("software-engineering-v1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
