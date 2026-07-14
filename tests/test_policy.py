import tempfile
import unittest
from pathlib import Path

from agent_security_gateway.policy import GatewayPolicy


class GatewayPolicyTests(unittest.TestCase):
    def test_loads_policy_from_json(self) -> None:
        policy = GatewayPolicy.load("config/default_policy.json")

        self.assertIn("developer", policy.role_permissions)
        self.assertIn("deploy", policy.approval_actions)
        self.assertEqual(policy.block_risk_at, 80)
        self.assertEqual(policy.policy_version, "default-v1")

    def test_validate_rejects_bad_threshold_order(self) -> None:
        policy = GatewayPolicy.from_dict(
            {
                "role_permissions": {"developer": ["read_file"]},
                "block_risk_at": 40,
                "require_approval_risk_at": 50,
            }
        )

        self.assertTrue(policy.validate())

    def test_loads_from_temporary_policy_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.json"
            path.write_text(
                """
                {
                  "role_permissions": {"analyst": ["read_file"]},
                  "approval_actions": [],
                  "blocked_tools": [],
                  "policy_version": "test-policy-v2",
                  "block_risk_at": 90,
                  "require_approval_risk_at": 40
                }
                """,
                encoding="utf-8",
            )

            policy = GatewayPolicy.load(path)

        self.assertEqual(policy.role_permissions["analyst"], {"read_file"})
        self.assertEqual(policy.policy_version, "test-policy-v2")


if __name__ == "__main__":
    unittest.main()
