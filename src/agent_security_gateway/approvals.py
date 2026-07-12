from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .models import AgentRequest, GatewayDecision


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    request_id: str
    status: str
    created_at: str
    request: dict
    decision: dict
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

    def _path(self, approval_id: str) -> Path:
        return self.directory / f"{approval_id}.json"

    @staticmethod
    def _write(path: Path, data: dict) -> None:
        with path.open("w", encoding="utf-8") as approval_file:
            json.dump(data, approval_file, indent=2)
            approval_file.write("\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
