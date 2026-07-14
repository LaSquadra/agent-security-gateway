from __future__ import annotations

from dataclasses import replace

from .models import AgentRequest, Provenance


def add_taint(provenance: Provenance, *labels: str) -> Provenance:
    merged = list(dict.fromkeys([*provenance.taint_labels, *labels]))
    return replace(provenance, taint_labels=merged)


def request_with_taint(request: AgentRequest, *labels: str) -> AgentRequest:
    return replace(request, provenance=add_taint(request.provenance, *labels))
