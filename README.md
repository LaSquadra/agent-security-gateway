# Agent Security Gateway

Agent Security Gateway is a portfolio project inspired by what I found interesting in the news and various research papers. It models a policy-enforcement proxy between an AI agent and its tools.

The gateway records provenance, assigns semantic risk scores, enforces least privilege, blocks suspicious flows, requires approval for sensitive actions, and emits OpenTelemetry-shaped trace events.

In one sentence: this project turns every agent tool call into a structured request, checks that request against policy and semantic risk signals, then returns `allow`, `block`, or `require_approval`.

## Why This Project

Modern agents can read repositories, call tools, update memory, open tickets, deploy code, and touch secrets. That creates a new AppSec boundary: natural-language instructions and retrieved content can influence privileged actions.

This project demonstrates how familiar security ideas map onto agent systems:

- Reference monitors for tool calls
- Least-privilege authorization
- Semantic risk scoring
- Human approval gates
- Provenance tracking
- Audit trails and trace events
- Prompt-injection and data-exfiltration controls

## How It Works

The gateway acts like a reference monitor between an AI agent and its tools:

```text
agent -> gateway -> tool
```

Instead of letting an agent directly call tools such as `read_file`, `write_file`, `deploy`, or `send_external`, the request is inspected first. The gateway asks four questions:

1. Is this agent role allowed to perform this action?
2. Does the request contain suspicious semantic signals?
3. Should the action be allowed, blocked, or routed to human approval?
4. What evidence should be written to traces and approval records?

The main unit of work is an `AgentRequest`. It includes the agent identity, role, requested tool, action, arguments, user intent, and provenance. Provenance means where the instruction or input came from, such as a trusted user, repository content, email, web content, or an uploaded file.

Policy enforcement is configured in `config/default_policy.json`. The policy defines role permissions, globally blocked tools, approval-required actions, and risk thresholds. This models least privilege: a researcher can read and search, a developer can modify code and run tests, and a release manager can perform deployment-oriented actions.

Risk scoring happens separately from authorization. The risk engine looks for prompt-injection language, secret-like terms, sensitive actions, low-trust provenance, and possible exfiltration. A request can be blocked even if the role normally has permission, because semantic risk and authorization are evaluated together.

The final decision is intentionally conservative:

```text
If either policy or risk says block -> block
Else if either says approval -> require approval
Else -> allow
```

For approval-required actions, the gateway writes a pending approval record to `approvals/`. For observability, it writes JSONL trace events to `traces/`, including `request_received`, `risk_scored`, `policy_evaluated`, and `decision_emitted`.

## Quick Start

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3 -m pip install -e .
asg demo
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
asg demo
```

You can also run the demo without installing the package:

```powershell
py -3 -m agent_security_gateway.cli demo
```

## CLI Workflow

Validate the default policy:

```powershell
asg validate-policy config/default_policy.json
```

Inspect a single request:

```powershell
asg inspect examples/prompt_injection_image.json --policy config/default_policy.json
```

Review an approval-required request:

```powershell
asg inspect examples/production_deploy.json --policy config/default_policy.json
asg resolve-approval <approval-id> approved --actor ryan
```

Route an MCP-style tool call through the gateway:

```powershell
asg mcp-call examples/mcp_low_risk_read_call.json --policy config/default_policy.json
```

## Delegation Roadmap

The project now includes an early control-plane model for delegated agent authority:

- `DelegationState` stores durable authority outside prompts and memory.
- `DelegationScope` limits which tools, actions, and resources an agent may use.
- `DelegationEnvelope` carries signed action-time authority with each delegated request.
- `AuthorizationStateStore` persists delegation records and revocation state.
- `EnvelopeSigner` signs and verifies envelopes using standard-library HMAC.

The gateway can validate delegated requests by checking the envelope signature, expiry, current delegation state, revocation epoch, agent identity, root principal, and requested scope before normal policy and risk checks run.

Approvals are now bound to the exact request context they approve: agent, tool, action, resource, delegation ID, and policy version. Approved records are single-use by default, so an approval for one action cannot be replayed against a different action or reused after consumption.

The gateway can also write an append-only decision ledger to `ledger/decisions.jsonl`. The ledger captures the request ID, trace ID, delegation context, root principal, approval ID, risk findings, reasons, and final decision for audit reconstruction.

The project also includes an MCP adapter stub. It accepts an MCP-like tool call, converts it into an `AgentRequest`, asks the gateway for a decision, and only invokes a registered tool handler when the decision is `allow`. This models where a real MCP proxy would enforce delegation, policy, risk, approval, and trace context before tool execution.

## Observability Model

Trace events and ledger entries are designed to support reconstruction and attribution.

Operational traces are written as JSONL events such as `request_received`, `risk_scored`, `policy_evaluated`, and `decision_emitted`. For delegated calls, the trace ID comes from the delegation envelope, so the same trace can follow an agent, sub-agent, and MCP-style tool hop.

Each trace event includes attribution fields such as:

- `request.id`
- `trace.id`
- `agent.id`
- `tool.name`
- `tool.action`
- `delegation.id`
- `delegation.parent_agent_id`
- `delegation.root_principal`
- `delegation.revocation_epoch`
- `approval.id`
- `policy.version`

The decision ledger records the same core identifiers plus risk findings, reasons, resource, and final decision. The intent is that traces help with operational debugging, while the ledger provides durable audit evidence for answering who acted, under which delegated authority, against which resource, under which policy version, and with what result.

See:

- `docs/architecture_roadmap.md`
- `docs/delegation_model.md`

## What The Demo Shows

The demo sends several simulated agent tool requests through the gateway:

- A low-risk file read is allowed.
- A write action is allowed only for an authorized role.
- A deployment action requires human approval.
- A request containing suspicious prompt-injection language is blocked.
- A request that tries to send secrets to an external destination is blocked.

Trace events are written to `traces/demo-traces.jsonl`.
Approval records are written to `approvals/` when a request requires human review.

## Walkthrough Script

If you are walking someone through the repo, use this order:

1. Start with this README and explain the project goal: a policy-enforcement gateway between agents and tools.
2. Open `config/default_policy.json` and explain roles, permissions, approval actions, blocked tools, and thresholds.
3. Open `examples/prompt_injection_image.json` and explain how untrusted content can influence an agent.
4. Open `src/agent_security_gateway/models.py` and explain the request, provenance, finding, decision, and trace models.
5. Open `src/agent_security_gateway/risk.py` and explain semantic risk scoring.
6. Open `src/agent_security_gateway/policy.py` and explain least-privilege authorization.
7. Open `src/agent_security_gateway/gateway.py` and show how policy and risk decisions are combined.
8. Open `src/agent_security_gateway/approvals.py` and `telemetry.py` to explain human review and auditability.

The short interview explanation:

> This project models a policy-enforcement gateway for AI agents. Instead of letting an agent directly execute tools, every tool call becomes a structured request. The gateway evaluates traditional authorization through role permissions, then evaluates AI-specific semantic risk such as prompt injection, secret handling, low-trust provenance, and possible exfiltration. It returns allow, block, or require approval. It also writes audit traces and creates approval records for sensitive actions.

## Project Structure

```text
agent-security-gateway/
  config/
    default_policy.json # Role permissions, thresholds, approval actions
  docs/
    *.md                # Architecture roadmap and delegation model notes
  examples/
    *.json              # Sample agent tool-call requests and attacks
  src/agent_security_gateway/
    approvals.py        # Pending approval records and resolution
    authz_state.py      # Durable delegation authorization state
    cli.py              # Command-line inspection workflow
    envelopes.py        # Signed delegation envelopes
    gateway.py          # Main policy enforcement flow
    io.py               # JSON request loading helpers
    ledger.py           # Append-only decision ledger
    mcp_adapter.py      # MCP-style tool-call adapter
    models.py           # Request, decision, provenance, and trace models
    policy.py           # Policy loading and evaluation
    risk.py             # Semantic and contextual risk scoring
    telemetry.py        # JSONL trace exporter
    demo.py             # Runnable portfolio demo
  tests/
    test_gateway.py
```

## Current Scope

This is intentionally a compact version 0.1. It does not call a real LLM or a live MCP server yet. Instead, it focuses on the security architecture that would sit between an agent runtime and real tools.

Good next milestones:

- Export real OpenTelemetry spans.
- Add taint tracking for retrieved content and memory writes.
- Build a small dashboard for reviewing blocked and approved tool calls.
- Add policy packs for AppSec, SOC, and software-engineering agents.

## Run Tests

```powershell
py -3 -m unittest discover -s tests
```

On macOS/Linux:

```bash
python3 -m unittest discover -s tests
```
