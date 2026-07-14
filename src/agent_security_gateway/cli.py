from __future__ import annotations

import argparse
import json
from pathlib import Path

from .approvals import ApprovalStore
from .dashboard import build_dashboard
from .demo import run_demo
from .gateway import AgentSecurityGateway
from .io import dump_json, load_request
from .ledger import DecisionLedger
from .mcp_adapter import McpGatewayAdapter, McpToolCall
from .policy import GatewayPolicy
from .policy_packs import list_policy_packs, load_policy_pack
from .showcase import run_showcase
from .telemetry import JsonlTraceExporter, OtlpJsonTraceExporter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="asg",
        description="Inspect AI agent tool calls through a security gateway.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser("demo", help="Run the bundled scenario demo.")
    demo_parser.add_argument("--policy", help="Path to a JSON policy file.")
    demo_parser.add_argument(
        "--trace-path", default="traces/demo-traces.jsonl", help="Trace JSONL output."
    )
    demo_parser.add_argument(
        "--trace-format",
        choices=["jsonl", "otlp-json"],
        default="jsonl",
        help="Trace output format.",
    )
    demo_parser.add_argument(
        "--approval-dir", default="approvals", help="Directory for approval records."
    )
    demo_parser.add_argument(
        "--ledger-path", default="ledger/decisions.jsonl", help="Decision ledger JSONL output."
    )

    showcase_parser = subparsers.add_parser(
        "showcase", help="Run a narrative end-to-end security showcase."
    )
    showcase_parser.add_argument(
        "--output-dir",
        default="showcase_output",
        help="Directory for showcase traces, approvals, ledgers, and OTLP output.",
    )
    showcase_parser.add_argument("--policy", help="Path to a JSON policy file.")
    showcase_parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Generate dashboard.html in the showcase output directory.",
    )

    dashboard_parser = subparsers.add_parser(
        "dashboard", help="Build a static HTML dashboard from generated artifacts."
    )
    dashboard_parser.add_argument(
        "--artifact-dir",
        default="showcase_output",
        help="Directory containing showcase or gateway artifacts.",
    )
    dashboard_parser.add_argument(
        "--output",
        help="Output HTML path. Defaults to <artifact-dir>/dashboard.html.",
    )
    showcase_parser.add_argument("--policy-pack", help="Named policy pack to use.")

    inspect_parser = subparsers.add_parser(
        "inspect", help="Inspect one request JSON file."
    )
    inspect_parser.add_argument("request", help="Path to an agent request JSON file.")
    inspect_parser.add_argument("--policy", help="Path to a JSON policy file.")
    inspect_parser.add_argument("--policy-pack", help="Named policy pack to use.")
    inspect_parser.add_argument(
        "--trace-path", default="traces/inspect-traces.jsonl", help="Trace JSONL output."
    )
    inspect_parser.add_argument(
        "--trace-format",
        choices=["jsonl", "otlp-json"],
        default="jsonl",
        help="Trace output format.",
    )
    inspect_parser.add_argument(
        "--approval-dir", default="approvals", help="Directory for approval records."
    )
    inspect_parser.add_argument(
        "--ledger-path", default="ledger/decisions.jsonl", help="Decision ledger JSONL output."
    )

    mcp_parser = subparsers.add_parser(
        "mcp-call", help="Route an MCP-style tool call through the gateway."
    )
    mcp_parser.add_argument("call", help="Path to an MCP-style tool-call JSON file.")
    mcp_parser.add_argument("--policy", help="Path to a JSON policy file.")
    mcp_parser.add_argument("--policy-pack", help="Named policy pack to use.")
    mcp_parser.add_argument(
        "--trace-path", default="traces/mcp-traces.jsonl", help="Trace JSONL output."
    )
    mcp_parser.add_argument(
        "--trace-format",
        choices=["jsonl", "otlp-json"],
        default="jsonl",
        help="Trace output format.",
    )
    mcp_parser.add_argument(
        "--approval-dir", default="approvals", help="Directory for approval records."
    )
    mcp_parser.add_argument(
        "--ledger-path", default="ledger/decisions.jsonl", help="Decision ledger JSONL output."
    )

    validate_parser = subparsers.add_parser(
        "validate-policy", help="Validate a JSON policy file."
    )
    validate_parser.add_argument("policy", help="Path to a JSON policy file.")

    packs_parser = subparsers.add_parser("policy-packs", help="List bundled policy packs.")
    packs_parser.add_argument(
        "--directory",
        default="policy_packs",
        help="Directory containing policy pack JSON files.",
    )

    approval_parser = subparsers.add_parser(
        "resolve-approval", help="Approve or deny a pending approval record."
    )
    approval_parser.add_argument("approval_id")
    approval_parser.add_argument("status", choices=["approved", "denied"])
    approval_parser.add_argument("--actor", default="human-reviewer")
    approval_parser.add_argument("--approval-dir", default="approvals")

    args = parser.parse_args(argv)

    if args.command == "demo":
        policy = _load_policy(args.policy)
        run_demo(
            policy,
            Path(args.trace_path),
            Path(args.approval_dir),
            Path(args.ledger_path),
            _trace_exporter(args.trace_path, args.trace_format),
        )
        return 0

    if args.command == "showcase":
        run_showcase(Path(args.output_dir), _load_policy(args.policy, args.policy_pack))
        if args.dashboard:
            dashboard_path = build_dashboard(args.output_dir)
            print(f"Dashboard written to {dashboard_path}")
        return 0

    if args.command == "dashboard":
        dashboard_path = build_dashboard(args.artifact_dir, args.output)
        print(f"Dashboard written to {dashboard_path}")
        return 0

    if args.command == "inspect":
        policy = _load_policy(args.policy, args.policy_pack)
        gateway = AgentSecurityGateway(
            policy=policy,
            trace_exporter=_trace_exporter(args.trace_path, args.trace_format),
            approval_store=ApprovalStore(args.approval_dir),
            decision_ledger=DecisionLedger(args.ledger_path),
        )
        decision = gateway.inspect(load_request(args.request))
        print(dump_json(decision.to_dict()))
        return 0

    if args.command == "mcp-call":
        policy = _load_policy(args.policy, args.policy_pack)
        gateway = AgentSecurityGateway(
            policy=policy,
            trace_exporter=_trace_exporter(args.trace_path, args.trace_format),
            approval_store=ApprovalStore(args.approval_dir),
            decision_ledger=DecisionLedger(args.ledger_path),
        )
        adapter = McpGatewayAdapter(gateway, tools=_demo_tools())
        with Path(args.call).open("r", encoding="utf-8") as call_file:
            call = McpToolCall.from_dict(json.load(call_file))
        result = adapter.handle_tool_call(call)
        print(dump_json(result.to_dict()))
        return 0

    if args.command == "validate-policy":
        policy = GatewayPolicy.load(args.policy)
        errors = policy.validate()
        if errors:
            for error in errors:
                print(f"ERROR: {error}")
            return 1
        print("Policy is valid.")
        return 0

    if args.command == "policy-packs":
        packs = list_policy_packs(args.directory)
        if not packs:
            print("No policy packs found.")
            return 1
        for pack in packs:
            policy = GatewayPolicy.load(pack)
            status = "valid" if not policy.validate() else "invalid"
            print(f"{pack.stem}: {policy.policy_version} ({status})")
        return 0

    if args.command == "resolve-approval":
        path = ApprovalStore(args.approval_dir).resolve(
            args.approval_id, args.status, args.actor
        )
        print(f"Approval record updated: {path}")
        return 0

    parser.error("Unknown command.")
    return 2


def _load_policy(path: str | None, pack: str | None = None) -> GatewayPolicy:
    if path and pack:
        raise ValueError("Use either --policy or --policy-pack, not both.")
    if pack:
        return load_policy_pack(pack)
    if path:
        return GatewayPolicy.load(path)
    default_path = Path("config/default_policy.json")
    if default_path.exists():
        return GatewayPolicy.load(default_path)
    return GatewayPolicy.default()


def _demo_tools():
    return {
        "filesystem.read_file": lambda arguments: {
            "content": f"simulated read of {arguments.get('path', '<missing path>')}"
        }
    }


def _trace_exporter(path: str, trace_format: str):
    if trace_format == "otlp-json":
        return OtlpJsonTraceExporter(path)
    return JsonlTraceExporter(path)


if __name__ == "__main__":
    raise SystemExit(main())
