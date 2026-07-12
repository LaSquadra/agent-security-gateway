# Agent Security Gateway

Agent Security Gateway is a portfolio project inspired by the July 12 AI and cybersecurity briefing. It models a policy-enforcement proxy between an AI agent and its tools.

The gateway records provenance, assigns semantic risk scores, enforces least privilege, blocks suspicious flows, requires approval for sensitive actions, and emits OpenTelemetry-shaped trace events.

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

## Quick Start

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3 -m pip install -e .
asg-demo
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
asg-demo
```

You can also run the demo without installing the package:

```powershell
py -3 -m agent_security_gateway.demo
```

## What The Demo Shows

The demo sends several simulated agent tool requests through the gateway:

- A low-risk file read is allowed.
- A write action is allowed only for an authorized role.
- A deployment action requires human approval.
- A request containing suspicious prompt-injection language is blocked.
- A request that tries to send secrets to an external destination is blocked.

Trace events are written to `traces/demo-traces.jsonl`.

## Project Structure

```text
agent-security-gateway/
  src/agent_security_gateway/
    gateway.py          # Main policy enforcement flow
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

- Add an MCP-compatible adapter.
- Export real OpenTelemetry spans.
- Add signed approval records.
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
