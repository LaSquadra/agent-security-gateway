from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .models import AgentRequest, ApprovalBinding, GatewayDecision


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    request_id: str
    status: str
    created_at: str
    request: dict
    decision: dict
    binding: dict
    history: list[dict] = field(default_factory=list)


class ApprovalStore:
    def __init__(self, directory: str | Path = "approvals") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def create(self, request: AgentRequest, decision: GatewayDecision) -> Path | None:
        if not decision.approval_id:
            return None

        record = ApprovalRecord(
            approval_id=decision.approval_id,
            request_id=request.request_id,
            status="pending",
            created_at=_now(),
            request=request.to_dict(),
            decision=decision.to_dict(),
            binding=asdict(ApprovalBinding.from_request(request)),
            history=[{"status": "pending", "changed_at": _now(), "actor": "gateway"}],
        )
        path = self._path(decision.approval_id)
        self._write(path, asdict(record))
        return path

    def resolve(self, approval_id: str, status: str, actor: str) -> Path:
        if status not in {"approved", "denied"}:
            raise ValueError("status must be 'approved' or 'denied'")

        path = self._path(approval_id)
        with path.open("r", encoding="utf-8") as approval_file:
            record = json.load(approval_file)

        record["status"] = status
        record.setdefault("history", []).append(
            {"status": status, "changed_at": _now(), "actor": actor}
        )
        self._write(path, record)
        return path

    def validate_and_consume(
        self,
        approval_id: str,
        request: AgentRequest,
        policy_version: str = "default",
    ) -> tuple[bool, str]:
        path = self._path(approval_id)
        with path.open("r", encoding="utf-8") as approval_file:
            record = json.load(approval_file)

        if record["status"] != "approved":
            return False, f"Approval '{approval_id}' is not approved."

        binding = ApprovalBinding.from_dict(record["binding"])
        if not binding.matches(request, policy_version):
            return False, f"Approval '{approval_id}' does not match this request."

        if binding.uses >= binding.max_uses:
            return False, f"Approval '{approval_id}' has already been used."

        updated_binding = ApprovalBinding(
            agent_id=binding.agent_id,
            tool_name=binding.tool_name,
            action=binding.action,
            resource=binding.resource,
            delegation_id=binding.delegation_id,
            policy_version=binding.policy_version,
            max_uses=binding.max_uses,
            uses=binding.uses + 1,
        )
        record["binding"] = asdict(updated_binding)
        record.setdefault("history", []).append(
            {"status": "consumed", "changed_at": _now(), "actor": "gateway"}
        )
        self._write(path, record)
        return True, f"Approval '{approval_id}' matched and was consumed."

    def _path(self, approval_id: str) -> Path:
        return self.directory / f"{approval_id}.json"

    @staticmethod
    def _write(path: Path, data: dict) -> None:
        with path.open("w", encoding="utf-8") as approval_file:
            json.dump(data, approval_file, indent=2)
            approval_file.write("\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
