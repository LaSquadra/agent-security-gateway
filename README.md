# Agent Security Gateway

Agent Security Gateway is a portfolio project for exploring **AI agent security engineering**. It models a policy-enforcement layer between autonomous agents and the tools they want to use.

The project turns every tool call into a structured request, evaluates authorization and semantic risk, handles delegated authority, binds approvals to exact actions, records audit evidence, and exposes an MCP-style adapter seam.

```text
agent or sub-agent
  -> signed delegation envelope
  -> Agent Security Gateway
  -> policy + risk + approval + revocation checks
  -> allow | block | require_approval
  -> traces + decision ledger
  -> tool execution only if allowed
```

## Why This Project

Modern AI agents can read files, modify code, invoke APIs, update tickets, interact with infrastructure, call MCP tools, and handle secrets. That creates a new AppSec boundary: natural-language instructions and retrieved content can influence privileged actions.

This project demonstrates how familiar security concepts map onto agent systems:

- Reference monitors for agent tool calls
- Least-privilege authorization
- Delegated authority and scope attenuation
- Signed capability-style envelopes
- Prompt-injection and exfiltration risk scoring
- Human approval gates
- Approval binding and replay prevention
- Provenance and taint tracking
- MCP-style tool-call mediation
- Trace correlation and append-only decision evidence

## What It Does Today

The current implementation is dependency-light and uses local JSON/JSONL files so the architecture is easy to inspect.

- `GatewayPolicy` loads role permissions, approval actions, blocked tools, thresholds, and `policy_version`.
- `AgentSecurityGateway` returns `allow`, `block`, or `require_approval`.
- `DelegationState` stores durable authority outside prompts and memory.
- `DelegationEnvelope` carries signed action-time authority with each delegated request.
- `AuthorizationStateStore` persists delegation state and revocation epochs.
- `ApprovalStore` creates pending approvals and validates single-use approval bindings.
- `DecisionLedger` writes append-only audit entries for reconstruction.
- `JsonlTraceExporter` emits OpenTelemetry-shaped JSONL trace events.
- `OtlpJsonTraceExporter` emits OTLP/HTTP-compatible JSON span payloads.
- `McpGatewayAdapter` converts MCP-style tool calls into gateway-inspected requests and only executes handlers after an `allow` decision.
- Taint labels on provenance model untrusted retrieved content, prompt-injection risk, secrets, credentials, or untrusted code.

This is not a production gateway yet. It does not run a real LLM, expose a live MCP server, or export native OpenTelemetry spans. It is an architecture lab showing where those integrations would fit.

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

Run without installing:

```powershell
py -3 -m agent_security_gateway.cli demo
```

## Showcase

For a portfolio walkthrough, use the narrative showcase:

```powershell
asg showcase
```

It runs a curated sequence:

- low-risk read allowed
- prompt-injection request blocked
- tainted external send blocked
- production deploy routed to approval
- approved deploy allowed once
- approval replay blocked
- delegated MCP-style read allowed and executed
- OTLP span export written

The showcase prints a compact table and writes reviewable artifacts to `showcase_output/`.

## CLI Workflow

Validate the default policy:

```powershell
asg validate-policy config/default_policy.json
```

Inspect a prompt-injection scenario:

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

Write OTLP-compatible JSON spans instead of JSONL traces:

```powershell
asg inspect examples/low_risk_read.json --trace-format otlp-json --trace-path traces/otlp-traces.json
```

## Core Flow

For each request, the gateway evaluates:

1. Delegation envelope signature, expiry, identity, scope, and revocation epoch.
2. Role-based policy permissions.
3. Semantic risk signals such as prompt injection, secret handling, sensitive actions, low-trust provenance, and possible exfiltration.
4. Approval binding, if an approval reference is supplied.
5. Trace and ledger evidence for reconstruction.

The final decision is conservative:

```text
If any control says block -> block
Else if any control says approval -> require_approval
Else -> allow
```

## Delegation And Approval Model

Delegated requests carry a signed `DelegationEnvelope` containing the delegation ID, agent ID, parent agent ID, root principal, scope reference, approval reference, revocation epoch, expiry, and trace ID.

The gateway validates the envelope against durable `DelegationState`. Child scopes must attenuate parent scopes: a child may receive less authority than its parent, but not more.

Approvals are bound to the exact request context they approve:

- agent
- tool
- action
- resource
- delegation ID
- policy version

Approved records are single-use by default. An approval for `deploy production` cannot be replayed for `deploy staging`, reused for `send_external`, or consumed a second time.

## Observability And Reconstruction

Trace events and ledger entries are designed to answer:

```text
Who acted?
Which agent or sub-agent made the request?
Which root principal delegated authority?
Which scope and revocation epoch were live?
Which approval applied?
Which policy version was used?
What resource was targeted?
Why was the action allowed, blocked, or routed to approval?
```

Operational traces are written as JSONL events such as `request_received`, `risk_scored`, `policy_evaluated`, and `decision_emitted`. The same events can also be exported as OTLP/HTTP-compatible JSON spans with `--trace-format otlp-json`.

For delegated calls, the trace ID comes from the delegation envelope, so the same trace can follow an agent, sub-agent, and MCP-style tool hop.

Trace events include attribution fields such as:

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

The decision ledger records the same core identifiers plus risk findings, reasons, resource, and final decision. Traces are for operational debugging; the ledger is for durable audit reconstruction.

## Taint Tracking

`Provenance` can carry `taint_labels` that describe risk inherited from retrieved content, uploads, web pages, or memory.

Current high-risk labels include:

- `prompt_injection`
- `secret`
- `credential`
- `untrusted_code`

The risk engine raises risk when tainted data flows into sensitive actions such as `send_external`, `write_file`, `deploy`, or `execute_shell`. Trace events and decision ledger entries both record taint labels so suspicious flows can be reconstructed later.

## What The Demo Shows

The demo sends several simulated agent tool requests through the gateway:

- A low-risk file read is allowed.
- A write action is allowed only for an authorized role.
- A deployment action requires human approval.
- A request containing suspicious prompt-injection language is blocked.
- A request that tries to send secrets to an external destination is blocked.

Demo output is written to:

```text
traces/demo-traces.jsonl
approvals/
ledger/decisions.jsonl
```

Generated traces, approvals, and ledgers are ignored by git.

## Project Structure

```text
agent-security-gateway/
  config/
    default_policy.json
  docs/
    architecture_roadmap.md
    delegation_model.md
  examples/
    delegated_read_request.json
    low_risk_read.json
    mcp_delegated_read_call.json
    mcp_low_risk_read_call.json
    production_deploy.json
    prompt_injection_image.json
    secret_exfiltration.json
    tainted_external_send.json
  src/agent_security_gateway/
    approvals.py        # Approval records, bindings, and replay prevention
    authz_state.py      # Durable delegation authorization state
    cli.py              # Command-line workflows
    demo.py             # Runnable scenario demo
    envelopes.py        # HMAC-signed delegation envelopes
    gateway.py          # Main enforcement flow
    io.py               # JSON request loading helpers
    ledger.py           # Append-only decision ledger
    mcp_adapter.py      # MCP-style tool-call adapter
    models.py           # Request, delegation, approval, decision, trace models
    policy.py           # Policy loading and evaluation
    risk.py             # Semantic and contextual risk scoring
    showcase.py         # Narrative portfolio demo
    taint.py            # Helpers for adding taint labels
    telemetry.py        # JSONL and OTLP-compatible trace exporters
  tests/
    test_approval_binding_and_ledger.py
    test_cli.py
    test_delegation.py
    test_gateway.py
    test_mcp_adapter.py
    test_policy.py
```

## Walkthrough Script

If you are walking someone through the repo, use this order:

1. Start with the architecture diagram at the top of this README.
2. Open `config/default_policy.json` and explain roles, permissions, approval actions, thresholds, and policy version.
3. Open `examples/prompt_injection_image.json` and explain how untrusted content can influence an agent.
4. Open `src/agent_security_gateway/models.py` and explain request, provenance, delegation, approval, decision, and trace models.
5. Open `src/agent_security_gateway/risk.py` and explain semantic risk scoring.
6. Open `src/agent_security_gateway/policy.py` and explain least-privilege authorization.
7. Open `src/agent_security_gateway/envelopes.py` and `authz_state.py` to explain signed delegation and durable state.
8. Open `src/agent_security_gateway/approvals.py` and explain approval binding and replay prevention.
9. Open `src/agent_security_gateway/gateway.py` and show how controls are combined.
10. Open `src/agent_security_gateway/mcp_adapter.py` and explain the MCP enforcement seam.
11. Open `src/agent_security_gateway/telemetry.py` and `ledger.py` to explain reconstruction and attribution.

Short interview explanation:

> This project models a security gateway for AI agents. Every tool call becomes a structured request. The gateway validates delegated authority, checks role-based policy, scores semantic risk, binds approvals to exact actions, and records trace plus ledger evidence. It can also mediate MCP-style tool calls, executing handlers only after an allow decision. The goal is to show how AppSec concepts like least privilege, reference monitors, provenance, delegated authorization, approval gates, and audit reconstruction apply to agentic AI systems.

## Run Tests

Windows PowerShell:

```powershell
py -3 -m unittest discover -s tests
```

macOS/Linux:

```bash
python3 -m unittest discover -s tests
```

Current coverage includes gateway decisions, policy validation, CLI workflows, delegation envelopes, scope attenuation, revocation and expiry checks, approval binding, replay prevention, decision ledger context, MCP adapter behavior, taint-sensitive flows, and trace/ledger attribution.

## Next Milestones

- Send OTLP spans directly to a collector endpoint.
- Extend taint tracking into memory writes and retrieved-document stores.
- Build a small dashboard for reviewing blocked and approved tool calls.
- Add policy packs for AppSec, SOC, and software-engineering agents.
- Replace the stubbed MCP adapter with a live MCP proxy/server integration.
