from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import AgentRequest, Decision


@dataclass(frozen=True)
class GatewayPolicy:
    policy_version: str = "default-v1"
    role_permissions: dict[str, set[str]] = field(default_factory=dict)
    approval_actions: set[str] = field(default_factory=set)
    blocked_tools: set[str] = field(default_factory=set)
    block_risk_at: int = 80
    require_approval_risk_at: int = 50

    @classmethod
    def default(cls) -> "GatewayPolicy":
        return cls(
            role_permissions={
                "researcher": {"read_file", "search_web", "write_report"},
                "developer": {"read_file", "write_file", "run_tests", "write_report"},
                "release_manager": {
                    "read_file",
                    "write_file",
                    "run_tests",
                    "deploy",
                    "write_report",
                    "send_external",
                },
            },
            approval_actions={"deploy", "delete", "send_external", "execute_shell"},
            blocked_tools={"raw_shell"},
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GatewayPolicy":
        role_permissions = {
            role: set(actions)
            for role, actions in data.get("role_permissions", {}).items()
        }
        return cls(
            policy_version=data.get("policy_version", "default-v1"),
            role_permissions=role_permissions,
            approval_actions=set(data.get("approval_actions", [])),
            blocked_tools=set(data.get("blocked_tools", [])),
            block_risk_at=int(data.get("block_risk_at", 80)),
            require_approval_risk_at=int(data.get("require_approval_risk_at", 50)),
        )

    @classmethod
    def load(cls, path: str | Path) -> "GatewayPolicy":
        with Path(path).open("r", encoding="utf-8") as policy_file:
            return cls.from_dict(json.load(policy_file))

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.role_permissions:
            errors.append("Policy must define at least one role permission set.")
        if self.block_risk_at <= self.require_approval_risk_at:
            errors.append("block_risk_at must be greater than require_approval_risk_at.")
        for role, actions in self.role_permissions.items():
            if not actions:
                errors.append(f"Role '{role}' must allow at least one action.")
        return errors

    def evaluate_permissions(self, request: AgentRequest) -> tuple[Decision, list[str]]:
        reasons: list[str] = []

        if request.tool_name in self.blocked_tools:
            return Decision.BLOCK, [f"Tool '{request.tool_name}' is globally blocked."]

        allowed_actions = self.role_permissions.get(request.role, set())
        if request.action not in allowed_actions:
            reasons.append(
                f"Role '{request.role}' is not allowed to perform '{request.action}'."
            )
            return Decision.BLOCK, reasons

        if request.action in self.approval_actions:
            reasons.append(f"Action '{request.action}' requires human approval.")
            return Decision.REQUIRE_APPROVAL, reasons

        return Decision.ALLOW, ["Role and tool permissions passed."]

    def evaluate_risk(self, risk_score: int) -> tuple[Decision, list[str]]:
        if risk_score >= self.block_risk_at:
            return Decision.BLOCK, [f"Risk score {risk_score} meets block threshold."]
        if risk_score >= self.require_approval_risk_at:
            return (
                Decision.REQUIRE_APPROVAL,
                [f"Risk score {risk_score} meets approval threshold."],
            )
        return Decision.ALLOW, [f"Risk score {risk_score} is within allow threshold."]
