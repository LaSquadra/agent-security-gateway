from __future__ import annotations

import argparse
from pathlib import Path

from .approvals import ApprovalStore
from .demo import run_demo
from .gateway import AgentSecurityGateway
from .io import dump_json, load_request
from .policy import GatewayPolicy
from .telemetry import JsonlTraceExporter


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
        "--approval-dir", default="approvals", help="Directory for approval records."
    )

    inspect_parser = subparsers.add_parser(
        "inspect", help="Inspect one request JSON file."
    )
    inspect_parser.add_argument("request", help="Path to an agent request JSON file.")
    inspect_parser.add_argument("--policy", help="Path to a JSON policy file.")
    inspect_parser.add_argument(
        "--trace-path", default="traces/inspect-traces.jsonl", help="Trace JSONL output."
    )
    inspect_parser.add_argument(
        "--approval-dir", default="approvals", help="Directory for approval records."
    )

    validate_parser = subparsers.add_parser(
        "validate-policy", help="Validate a JSON policy file."
    )
    validate_parser.add_argument("policy", help="Path to a JSON policy file.")

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
        run_demo(policy, Path(args.trace_path), Path(args.approval_dir))
        return 0

    if args.command == "inspect":
        policy = _load_policy(args.policy)
        gateway = AgentSecurityGateway(
            policy=policy,
            trace_exporter=JsonlTraceExporter(args.trace_path),
            approval_store=ApprovalStore(args.approval_dir),
        )
        decision = gateway.inspect(load_request(args.request))
        print(dump_json(decision.to_dict()))
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

    if args.command == "resolve-approval":
        path = ApprovalStore(args.approval_dir).resolve(
            args.approval_id, args.status, args.actor
        )
        print(f"Approval record updated: {path}")
        return 0

    parser.error("Unknown command.")
    return 2


def _load_policy(path: str | None) -> GatewayPolicy:
    if path:
        return GatewayPolicy.load(path)
    default_path = Path("config/default_policy.json")
    if default_path.exists():
        return GatewayPolicy.load(default_path)
    return GatewayPolicy.default()


if __name__ == "__main__":
    raise SystemExit(main())
