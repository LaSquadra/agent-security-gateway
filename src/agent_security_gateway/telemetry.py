from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .models import AgentRequest, GatewayDecision, TraceEvent


class JsonlTraceExporter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit_decision(self, request: AgentRequest, decision: GatewayDecision) -> None:
        events = build_trace_events(request, decision)

        with self.path.open("a", encoding="utf-8") as trace_file:
            for event in events:
                trace_file.write(json.dumps(event.to_dict()) + "\n")


class OtlpJsonTraceExporter:
    def __init__(
        self,
        path: str | Path = "traces/otlp-traces.json",
        service_name: str = "agent-security-gateway",
    ) -> None:
        self.path = Path(path)
        self.service_name = service_name
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit_decision(self, request: AgentRequest, decision: GatewayDecision) -> None:
        events = build_trace_events(request, decision)
        payload = trace_events_to_otlp_json(events, self.service_name)
        with self.path.open("w", encoding="utf-8") as trace_file:
            json.dump(payload, trace_file, indent=2)
            trace_file.write("\n")


def build_trace_events(
    request: AgentRequest, decision: GatewayDecision
) -> list[TraceEvent]:
    root_span_id = _span_id()
    trace_id = _trace_id(request)
    return [
        _event(request, decision, trace_id, root_span_id, None, "request_received", "ok", 0, {}),
        _event(
            request,
            decision,
            trace_id,
            _span_id(),
            root_span_id,
            "risk_scored",
            "ok",
            1,
            {
                "security.risk_score": decision.risk_score,
                "security.findings": [
                    finding.__dict__ for finding in decision.findings
                ],
            },
        ),
        _event(
            request,
            decision,
            trace_id,
            _span_id(),
            root_span_id,
            "policy_evaluated",
            "ok",
            1,
            {"security.reasons": decision.reasons},
        ),
        _event(
            request,
            decision,
            trace_id,
            _span_id(),
            root_span_id,
            "decision_emitted",
            decision.decision.value,
            1,
            {
                "security.decision": decision.decision.value,
                "security.approval_id": decision.approval_id,
            },
        ),
    ]


def trace_events_to_otlp_json(
    events: list[TraceEvent], service_name: str = "agent-security-gateway"
) -> dict:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _otlp_attribute("service.name", service_name),
                        _otlp_attribute("telemetry.sdk.language", "python"),
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "agent_security_gateway"},
                        "spans": [_trace_event_to_otlp_span(event) for event in events],
                    }
                ],
            }
        ]
    }


def _trace_event_to_otlp_span(event: TraceEvent) -> dict:
    start = _parse_timestamp(event.timestamp)
    end = start + timedelta(milliseconds=event.duration_ms)
    span = {
        "traceId": _hex_id(event.trace_id, 32),
        "spanId": _hex_id(event.span_id, 16),
        "name": event.name,
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": str(_unix_nano(start)),
        "endTimeUnixNano": str(_unix_nano(end)),
        "attributes": [
            _otlp_attribute(key, value)
            for key, value in event.attributes.items()
            if value is not None
        ],
        "status": {"code": _otlp_status_code(event.status)},
    }
    if event.parent_span_id:
        span["parentSpanId"] = _hex_id(event.parent_span_id, 16)
    return span


def _event(
    request: AgentRequest,
    decision: GatewayDecision,
    trace_id: str,
    span_id: str,
    parent_span_id: str | None,
    event_type: str,
    status: str,
    duration_ms: int,
    extra_attributes: dict,
) -> TraceEvent:
    return TraceEvent(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        name=f"agent_security_gateway.{event_type}",
        timestamp=request.timestamp,
        duration_ms=duration_ms,
        status=status,
        attributes={
            "request.id": request.request_id,
            "trace.id": trace_id,
            "agent.id": request.agent_id,
            "agent.role": request.role,
            "tool.name": request.tool_name,
            "tool.action": request.action,
            "policy.version": decision.policy_version,
            "approval.id": decision.approval_id,
            "provenance.source": request.provenance.source,
            "provenance.trust_level": request.provenance.trust_level,
            "provenance.taint_labels": request.provenance.taint_labels,
            **_delegation_attributes(request),
            **extra_attributes,
        },
    )


def _trace_id(request: AgentRequest) -> str:
    return request.delegation.trace_id if request.delegation else request.request_id


def _span_id() -> str:
    return uuid4().hex[:16]


def _delegation_attributes(request: AgentRequest) -> dict:
    if not request.delegation:
        return {
            "delegation.id": None,
            "delegation.parent_agent_id": None,
            "delegation.root_principal": None,
            "delegation.revocation_epoch": None,
        }
    return {
        "delegation.id": request.delegation.delegation_id,
        "delegation.parent_agent_id": request.delegation.parent_agent_id,
        "delegation.root_principal": request.delegation.root_principal,
        "delegation.revocation_epoch": request.delegation.revocation_epoch,
    }


def _otlp_attribute(key: str, value) -> dict:
    return {"key": key, "value": _otlp_any_value(value)}


def _otlp_any_value(value) -> dict:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, list):
        return {
            "arrayValue": {
                "values": [_otlp_any_value(item) for item in value]
            }
        }
    if isinstance(value, dict):
        return {
            "kvlistValue": {
                "values": [
                    _otlp_attribute(str(item_key), item_value)
                    for item_key, item_value in value.items()
                ]
            }
        }
    return {"stringValue": str(value)}


def _otlp_status_code(status: str) -> str:
    return "STATUS_CODE_OK" if status in {"ok", "allow"} else "STATUS_CODE_ERROR"


def _hex_id(value: str, length: int) -> str:
    cleaned = "".join(char for char in value.lower() if char in "0123456789abcdef")
    if len(cleaned) >= length:
        return cleaned[:length]
    return cleaned.ljust(length, "0")


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _unix_nano(value: datetime) -> int:
    return int(value.timestamp() * 1_000_000_000)
