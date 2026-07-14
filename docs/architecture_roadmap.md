# Agent Security Gateway Architecture Roadmap

This project currently acts as a reference monitor for agent tool calls. The next architectural goal is to make it model action-time control-plane enforcement across agents, sub-agents, and MCP/tool hops.

## Target Shape

```text
agent or sub-agent
  -> signed delegation envelope
  -> Agent Security Gateway
  -> authorization-state store
  -> policy + risk + approval + revocation join
  -> allow | block | require_approval
  -> traces + decision ledger
```

## Proposed Developments

1. Durable delegation-state storage
   - Store delegation records outside agent prompts, memory, and process state.
   - Track root principal, parent agent, child agent, permitted scope, expiry, status, and revocation epoch.

2. Scope attenuation for sub-agents
   - Child agents may receive less authority than parents, but never more.
   - Scope should cover tools, actions, and resource constraints.

3. Signed delegation envelopes
   - Each privileged tool call should carry a compact envelope.
   - The gateway validates signature, expiry, delegation identity, and revocation epoch before evaluating the tool call.

4. Per-action revocation checks
   - Revocation is checked at action time, not only when the agent starts.
   - A stale envelope must fail if the durable delegation state has moved to a newer revocation epoch.

5. Approval binding and replay prevention
   - Approvals should bind to a delegation, tool, action, resource, policy version, expiry, and optional use count.
   - This prevents an approval for one action from being replayed against a different action.

6. Live MCP gateway integration
   - Add an adapter that can intercept MCP tool requests and responses.
   - The adapter should translate MCP calls into `AgentRequest` objects and route decisions back to the caller.

7. Cross-hop distributed tracing
   - Preserve trace context across agents, sub-agents, gateways, and tool servers.
   - Record delegation IDs, parent-child relationships, risk findings, policy versions, and final decisions.

8. Append-only decision ledger
   - Add a durable, JSONL-backed ledger for reconstructing security decisions.
   - The ledger should be separate from operational traces and suitable for audit review.

9. Taint tracking
   - Carry taint labels from retrieved content, uploaded files, web inputs, and memory.
   - Raise risk when tainted data flows into sensitive actions.
   - Preserve taint labels in traces and decision ledger entries.

## Milestone 1 Status

Milestone 1 begins the control-plane model with:

- `DelegationScope`
- `DelegationState`
- `DelegationEnvelope`
- JSON-backed `AuthorizationStateStore`
- HMAC-backed `EnvelopeSigner`
- Gateway validation for delegated requests

This keeps the project dependency-light while making the next steps concrete.

## Milestone 2 Status

Milestone 2 adds approval binding and audit evidence:

- Approvals bind to agent, tool, action, resource, delegation ID, and policy version.
- Approved records are single-use by default.
- A bound approval can convert a `require_approval` decision into `allow` only for the matching request.
- Mismatched or already-consumed approvals produce a `block` decision.
- `DecisionLedger` writes JSONL audit entries with delegation, approval, risk, and decision context.

This gives the project the action-time evidence needed to answer: which scope was live, which approval applied, and what decision was made for that tool call?

## Milestone 3 Status

Milestone 3 adds an MCP adapter stub:

- `McpToolCall` models an MCP-style tool invocation.
- `McpGatewayAdapter` converts tool calls into `AgentRequest` objects.
- The adapter executes registered handlers only after an `allow` decision.
- Blocked or approval-required calls do not execute.
- Delegation trace IDs and parent-agent context are preserved in the decision ledger.

This is not a full MCP server yet. It is the integration seam where a real MCP proxy can be added later.

## Milestone 4 Status

Milestone 4 strengthens reconstruction and attribution:

- Policies now carry a `policy_version`.
- Gateway decisions include the policy version used for evaluation.
- Approval bindings and decision ledger entries record policy version.
- Trace IDs use the delegation envelope trace ID when present.
- Trace events include request, trace, delegation, parent-agent, root-principal, revocation, approval, and policy metadata.
- Tests verify that MCP trace events and decision ledger entries share the same attribution context.

This gives the project a clearer answer to post-incident questions: who acted, through which delegation chain, under which policy, with which approval, against which resource, and what decision was made?

## Milestone 5 Status

Milestone 5 adds taint-aware risk and evidence:

- `Provenance` can carry `taint_labels`.
- The risk engine scores high-risk taint labels.
- Sensitive flows involving tainted input increase risk and can block.
- Trace events and decision ledger entries record taint labels.
- Tests cover tainted sensitive flows and trace/ledger taint attribution.

This makes provenance more than source metadata: it now carries risk forward from untrusted content into action-time decisions.

## Milestone 6 Status

Milestone 6 adds OTLP-compatible span export:

- Trace events are generated once and shared by JSONL and OTLP exporters.
- `OtlpJsonTraceExporter` writes OTLP/HTTP-compatible JSON payloads.
- CLI commands support `--trace-format jsonl` and `--trace-format otlp-json`.
- OTLP spans include resource attributes, scope spans, trace IDs, span IDs, parent span IDs, timestamps, status, and security attribution attributes.
- Tests verify OTLP payload structure and CLI output.

This keeps the project dependency-light while making the trace output compatible with OpenTelemetry collector ingestion paths that accept protobuf-JSON OTLP payloads.

## Milestone 7 Status

Milestone 7 adds a narrative showcase:

- `asg showcase` runs the major security scenarios in one command.
- The showcase prints a compact decision table for live walkthroughs.
- It writes traces, approvals, ledgers, MCP evidence, and OTLP JSON output to `showcase_output/`.
- Tests verify that the showcase runs and produces expected artifacts.

This gives the project a human-friendly demonstration path separate from the test suite.
