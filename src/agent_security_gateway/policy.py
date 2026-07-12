from __future__ import annotations

from dataclasses import dataclass, field

from .models import AgentRequest, Decision


@dataclass(frozen=True)
class GatewayPolicy:
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
                },
            },
            approval_actions={"deploy", "delete", "send_external", "execute_shell"},
            blocked_tools={"raw_shell"},
        )

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
