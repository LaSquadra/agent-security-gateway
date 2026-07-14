from __future__ import annotations

import json
from pathlib import Path

from .models import DelegationScope, DelegationState


class AuthorizationStateStore:
    def __init__(self, directory: str | Path = "data/delegations") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def create(self, state: DelegationState) -> Path:
        if state.parent_delegation_id:
            parent = self.load(state.parent_delegation_id)
            if not state.scope.attenuates(parent.scope):
                raise ValueError("child delegation scope cannot exceed parent scope")
        path = self._path(state.delegation_id)
        self._write(path, state.to_dict())
        return path

    def create_child(
        self,
        *,
        delegation_id: str,
        agent_id: str,
        parent_delegation_id: str,
        scope: DelegationScope,
        approval_ref: str | None = None,
        expires_at: str | None = None,
    ) -> DelegationState:
        parent = self.load(parent_delegation_id)
        child = DelegationState(
            delegation_id=delegation_id,
            agent_id=agent_id,
            root_principal=parent.root_principal,
            scope=scope,
            parent_agent_id=parent.agent_id,
            parent_delegation_id=parent.delegation_id,
            approval_ref=approval_ref,
            revocation_epoch=parent.revocation_epoch,
            expires_at=expires_at or parent.expires_at,
        )
        self.create(child)
        return child

    def load(self, delegation_id: str) -> DelegationState:
        path = self._path(delegation_id)
        with path.open("r", encoding="utf-8") as state_file:
            return DelegationState.from_dict(json.load(state_file))

    def revoke(self, delegation_id: str) -> DelegationState:
        current = self.load(delegation_id)
        revoked = DelegationState(
            delegation_id=current.delegation_id,
            agent_id=current.agent_id,
            root_principal=current.root_principal,
            scope=current.scope,
            parent_agent_id=current.parent_agent_id,
            parent_delegation_id=current.parent_delegation_id,
            approval_ref=current.approval_ref,
            revocation_epoch=current.revocation_epoch + 1,
            status="revoked",
            issued_at=current.issued_at,
            expires_at=current.expires_at,
        )
        self._write(self._path(delegation_id), revoked.to_dict())
        return revoked

    def _path(self, delegation_id: str) -> Path:
        return self.directory / f"{delegation_id}.json"

    @staticmethod
    def _write(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as state_file:
            json.dump(data, state_file, indent=2)
            state_file.write("\n")
