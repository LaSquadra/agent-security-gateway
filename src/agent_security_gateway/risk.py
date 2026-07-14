from __future__ import annotations

from collections.abc import Iterable

from .models import AgentRequest, RiskFinding


PROMPT_INJECTION_TERMS = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "system prompt",
    "developer message",
    "exfiltrate",
    "bypass policy",
    "disable safety",
)

SECRET_TERMS = (
    "api_key",
    "api key",
    "secret",
    "token",
    "password",
    "credential",
    "private key",
)

SENSITIVE_ACTIONS = {"deploy", "delete", "write", "send_external", "execute_shell"}
LOW_TRUST_SOURCES = {"web", "email", "user_upload", "unknown"}
HIGH_RISK_TAINTS = {"prompt_injection", "secret", "credential", "untrusted_code"}


def score_request(request: AgentRequest) -> tuple[int, list[RiskFinding]]:
    text = _request_text(request)
    findings: list[RiskFinding] = []

    findings.extend(_match_terms("prompt_injection", text, PROMPT_INJECTION_TERMS, 60))
    findings.extend(_match_terms("secret_handling", text, SECRET_TERMS, 35))

    if request.action in SENSITIVE_ACTIONS:
        findings.append(
            RiskFinding(
                "sensitive_action",
                30,
                f"Action '{request.action}' can change state or expose data.",
            )
        )

    if request.provenance.trust_level in LOW_TRUST_SOURCES:
        findings.append(
            RiskFinding(
                "low_trust_provenance",
                20,
                f"Input came from low-trust source '{request.provenance.trust_level}'.",
            )
        )

    matched_taints = set(request.provenance.taint_labels).intersection(HIGH_RISK_TAINTS)
    for taint in sorted(matched_taints):
        findings.append(
            RiskFinding(
                "tainted_provenance",
                45,
                f"Provenance carries high-risk taint label '{taint}'.",
            )
        )

    if request.action == "send_external" and any(term in text for term in SECRET_TERMS):
        findings.append(
            RiskFinding(
                "possible_exfiltration",
                70,
                "Request combines external transfer with secret-like content.",
            )
        )

    if (
        request.action in {"send_external", "write_file", "deploy", "execute_shell"}
        and request.provenance.taint_labels
    ):
        findings.append(
            RiskFinding(
                "tainted_sensitive_flow",
                40,
                "Tainted input is flowing into a sensitive action.",
            )
        )

    total = min(100, sum(finding.score for finding in findings))
    return total, findings


def _request_text(request: AgentRequest) -> str:
    parts = [
        request.tool_name,
        request.action,
        request.user_intent,
        str(request.arguments),
        request.provenance.source,
        request.provenance.retrieved_from or "",
        " ".join(request.provenance.taint_labels),
    ]
    return " ".join(parts).lower()


def _match_terms(
    category: str, text: str, terms: Iterable[str], score: int
) -> list[RiskFinding]:
    return [
        RiskFinding(category, score, f"Matched suspicious term '{term}'.")
        for term in terms
        if term in text
    ]
