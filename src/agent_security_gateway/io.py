from __future__ import annotations

import json
from pathlib import Path

from .models import AgentRequest


def load_request(path: str | Path) -> AgentRequest:
    with Path(path).open("r", encoding="utf-8") as request_file:
        return AgentRequest.from_dict(json.load(request_file))


def dump_json(data: dict) -> str:
    return json.dumps(data, indent=2)
