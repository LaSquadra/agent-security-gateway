# Delegation Model

The delegation model answers a specific question:

> When an agent or sub-agent invokes a tool, what authority is live for that exact action?

The gateway should not trust the agent's prompt, memory, or self-description. Instead, each delegated request carries a signed envelope that points back to durable authorization state.

## Delegation State

A delegation state record contains:

```text
delegation_id
agent_id
root_principal
parent_agent_id
parent_delegation_id
scope
approval_ref
revocation_epoch
status
issued_at
expires_at
```

This is the durable source of truth. In the current implementation it is JSON-backed for simplicity.

## Delegation Scope

A scope contains:

```text
tools
actions
resources
```

The gateway checks the requested tool, action, and optional resource against this scope.

## Scope Attenuation

When a parent delegates to a child, the child scope must be a subset of the parent scope.

Allowed:

```text
parent: tools=[filesystem, deployment], actions=[read_file, deploy]
child:  tools=[filesystem], actions=[read_file]
```

Rejected:

```text
parent: actions=[read_file]
child:  actions=[deploy]
```

## Signed Envelope

The envelope is the small object that travels with a request:

```json
{
  "delegation_id": "dlg-child-7",
  "agent_id": "agent-child-7",
  "parent_agent_id": "agent-root-1",
  "root_principal": "user:ryan",
  "scope_ref": "scope-child-read",
  "approval_ref": null,
  "revocation_epoch": 0,
  "expires_at": "2099-01-01T00:00:00Z",
  "trace_id": "trace-abc",
  "signature": "..."
}
```

The gateway validates signature, expiry, current delegation state, revocation epoch, agent identity, root principal, and scope before the normal policy and risk checks run.
