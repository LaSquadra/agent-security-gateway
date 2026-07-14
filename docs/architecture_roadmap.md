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

## Milestone 1 Status

Milestone 1 begins the control-plane model with:

- `DelegationScope`
- `DelegationState`
- `DelegationEnvelope`
- JSON-backed `AuthorizationStateStore`
- HMAC-backed `EnvelopeSigner`
- Gateway validation for delegated requests

This keeps the project dependency-light while making the next steps concrete.
