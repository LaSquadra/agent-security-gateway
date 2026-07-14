from __future__ import annotations

import json
from html import escape
from pathlib import Path


def build_dashboard(
    artifact_dir: str | Path = "showcase_output",
    output_path: str | Path | None = None,
) -> Path:
    artifact_root = Path(artifact_dir)
    destination = Path(output_path) if output_path else artifact_root / "dashboard.html"
    destination.parent.mkdir(parents=True, exist_ok=True)

    ledger_entries = _read_jsonl_files(
        [
            artifact_root / "decisions.jsonl",
            artifact_root / "mcp-decisions.jsonl",
        ]
    )
    approvals = _read_approval_files(artifact_root / "approvals")
    trace_count = sum(
        len(_read_jsonl(path))
        for path in [artifact_root / "traces.jsonl", artifact_root / "mcp-traces.jsonl"]
    )
    otlp_exists = (artifact_root / "otlp-traces.json").exists()

    destination.write_text(
        _render_dashboard(artifact_root, ledger_entries, approvals, trace_count, otlp_exists),
        encoding="utf-8",
    )
    return destination


def _read_jsonl_files(paths: list[Path]) -> list[dict]:
    entries: list[dict] = []
    for path in paths:
        entries.extend(_read_jsonl(path))
    return entries


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _read_approval_files(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(item.read_text(encoding="utf-8"))
        for item in sorted(path.glob("approval-*.json"))
    ]


def _render_dashboard(
    artifact_root: Path,
    ledger_entries: list[dict],
    approvals: list[dict],
    trace_count: int,
    otlp_exists: bool,
) -> str:
    total = len(ledger_entries)
    allowed = _count(ledger_entries, "allow")
    blocked = _count(ledger_entries, "block")
    approvals_required = _count(ledger_entries, "require_approval")
    tainted = sum(1 for entry in ledger_entries if entry.get("provenance_taint_labels"))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent Security Gateway Dashboard</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #17202a; }}
    h1 {{ margin-bottom: 4px; }}
    .muted {{ color: #5f6b7a; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 24px 0; }}
    .stat {{ border: 1px solid #d6dde5; border-radius: 6px; padding: 14px; }}
    .stat strong {{ display: block; font-size: 28px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 18px 0 32px; }}
    th, td {{ border: 1px solid #d6dde5; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f4f7fa; }}
    code {{ background: #f4f7fa; padding: 2px 4px; border-radius: 4px; }}
    .allow {{ color: #137333; font-weight: 600; }}
    .block {{ color: #b3261e; font-weight: 600; }}
    .require_approval {{ color: #8a5a00; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Agent Security Gateway Dashboard</h1>
  <p class="muted">Artifacts: <code>{escape(str(artifact_root))}</code></p>

  <section class="stats">
    {_stat("Decisions", total)}
    {_stat("Allowed", allowed)}
    {_stat("Blocked", blocked)}
    {_stat("Approval Required", approvals_required)}
    {_stat("Tainted Flows", tainted)}
    {_stat("Trace Events", trace_count)}
    {_stat("Approvals", len(approvals))}
    {_stat("OTLP Export", "yes" if otlp_exists else "no")}
  </section>

  <h2>Decision Ledger</h2>
  {_decision_table(ledger_entries)}

  <h2>Approval Records</h2>
  {_approval_table(approvals)}
</body>
</html>
"""


def _stat(label: str, value) -> str:
    return f'<div class="stat"><span>{escape(label)}</span><strong>{escape(str(value))}</strong></div>'


def _decision_table(entries: list[dict]) -> str:
    if not entries:
        return "<p>No decision ledger entries found.</p>"
    rows = []
    for entry in entries:
        decision = escape(str(entry.get("decision", "")))
        rows.append(
            "<tr>"
            f"<td>{escape(str(entry.get('timestamp', '')))}</td>"
            f"<td class=\"{decision}\">{decision}</td>"
            f"<td>{escape(str(entry.get('risk_score', '')))}</td>"
            f"<td>{escape(str(entry.get('agent_id', '')))}</td>"
            f"<td>{escape(str(entry.get('tool_name', '')))}.{escape(str(entry.get('action', '')))}</td>"
            f"<td>{escape(str(entry.get('resource', '')))}</td>"
            f"<td>{escape(str(entry.get('delegation_id', '')))}</td>"
            f"<td>{escape(str(entry.get('approval_id', '')))}</td>"
            f"<td>{escape(', '.join(entry.get('provenance_taint_labels', [])))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Time</th><th>Decision</th><th>Risk</th>"
        "<th>Agent</th><th>Tool Action</th><th>Resource</th><th>Delegation</th>"
        "<th>Approval</th><th>Taint</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _approval_table(approvals: list[dict]) -> str:
    if not approvals:
        return "<p>No approval records found.</p>"
    rows = []
    for approval in approvals:
        binding = approval.get("binding", {})
        rows.append(
            "<tr>"
            f"<td>{escape(str(approval.get('approval_id', '')))}</td>"
            f"<td>{escape(str(approval.get('status', '')))}</td>"
            f"<td>{escape(str(binding.get('agent_id', '')))}</td>"
            f"<td>{escape(str(binding.get('tool_name', '')))}.{escape(str(binding.get('action', '')))}</td>"
            f"<td>{escape(str(binding.get('resource', '')))}</td>"
            f"<td>{escape(str(binding.get('uses', '')))} / {escape(str(binding.get('max_uses', '')))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Approval</th><th>Status</th><th>Agent</th>"
        "<th>Bound Action</th><th>Resource</th><th>Uses</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _count(entries: list[dict], decision: str) -> int:
    return sum(1 for entry in entries if entry.get("decision") == decision)
