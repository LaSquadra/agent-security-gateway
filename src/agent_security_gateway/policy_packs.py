from __future__ import annotations

from pathlib import Path

from .policy import GatewayPolicy


DEFAULT_POLICY_PACK_DIR = Path("policy_packs")


def list_policy_packs(directory: str | Path = DEFAULT_POLICY_PACK_DIR) -> list[Path]:
    path = Path(directory)
    if not path.exists():
        return []
    return sorted(path.glob("*.json"))


def load_policy_pack(name: str, directory: str | Path = DEFAULT_POLICY_PACK_DIR) -> GatewayPolicy:
    candidate = Path(name)
    if candidate.exists():
        return GatewayPolicy.load(candidate)

    pack_path = Path(directory) / f"{name}.json"
    return GatewayPolicy.load(pack_path)
