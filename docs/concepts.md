# Concepts

## The pipeline

Every guarded call takes the same path, whether it comes from the decorator, an adapter,
MCP or `guard.call(name, arguments)`:

```text
Agent proposes a tool call
  → 1. Validate      strict types, size limit, paths made absolute, URLs/commands checked
  → 2. Policy        rules: allow / ask / deny
  → 3. Risk          0–100 deterministic score; some patterns always deny
  → 4. Judge         optional Gemma review; can only raise risk
  → 5. Approval      a human decides "ask" actions, once
  → 6. Execute       the tool, or a controlled executor in its place
  → 7. Verify        optional before/after workspace hashes
  → 8. Audit         every stage appended to a hash-chained log
```

If any step fails, the call is denied and the tool does not run. If execution or
verification fails, the session halts: further calls are denied until a new Guard is made.

## Trust boundary

| Untrusted | Trusted |
| --- | --- |
| The model and its tool arguments | Your application code and tool registration |
| Files, web pages and tool output it reads | The policy, executors and approval providers |
| | The Python runtime and operating system |

The model controls only the tool **name** and **arguments**. The capability label, working
directory, environment and agent identity come from your code. A prompt injection cannot
relabel `shell.execute` as `filesystem.read`.

AgentGuard is an interception layer for cooperative applications. It protects the tools
you route through it. An agent that also has unguarded tools, raw shell access or Python
`exec` can go around it. See the [threat model](security.md).

## Capabilities

Each tool declares one capability. Built-in capabilities and their baseline risk:

| Capability | Baseline | Notes |
| --- | --- | --- |
| `filesystem.read` | 5 | Needs a `path` argument |
| `filesystem.write` | 28 | Needs `path`; `content` for `FilesystemExecutor` |
| `filesystem.delete` | 65 | Needs `path` |
| `shell.execute` | 40 | Needs `cmd` or `command` |
| `repository.write` | 45 | Needs `cmd` or `command`; counts as outbound |
| `network.request` | 30 | Needs `url`; outbound |
| `email.send` | 55 | Recipient limit applies; outbound |
| `message.send` | 55 | Recipient limit applies; outbound |

Policies can declare [custom capabilities](policy.md#custom-capabilities) such as
`db.query` or `payments.refund`, and tools can map their own parameter names to these
roles. See [Registering tools](tools.md).

## How a decision is made

1. **Policy.** Any matching rule with `effect: deny` wins. Otherwise the first matching rule
   decides. If none match, the default applies (deny unless you change it).
2. **Risk.** The score starts at the capability baseline and rises with context: production
   environment, secrets in arguments, pushes to protected branches, external transfer
   commands, repeated denials. Some findings are a **hard deny**:
    - credential files (`.ssh`, `.aws`, `.env`, `id_rsa`, ...)
    - destructive commands (`rm -rf`, `sudo`, `mkfs`, `format C:`, download-and-execute)
    - secrets in an outbound action
    - any outbound action after a tool returned a secret in this session (session taint)
3. **Thresholds.** Risk at or above `ask` (default 51) turns an allow into ask. At or above
   `strong` (76) the approver must perform strong approval. At or above `deny` (91), or on
   a hard deny, the call is denied.
4. **Approval.** Never overrides a deny. Rejection, a timeout, a missing approver or a
   malformed answer means deny.

`agentguard explain` shows each step for a given call. See [CLI](cli.md#explain).

## Modes

- **`mode="enforce"`** (default): decisions are enforced.
- **`mode="dry-run"`**: valid calls *really execute*, including ones policy would deny,
  and the audit log records what would have happened. Use it to tune a policy on safe
  workloads, never on an untrusted agent. `guard.summary` counts evaluated decisions.

## Sessions

A session is one agent run: its own lock, rate window, taint state and halt flag. A Guard
starts with a default session; `guard.new_session(agent_id=...)` creates more, which share
the Guard's tools, policy, audit and approval and run in parallel. Calls within one session
are serialized. Tools may make nested guarded calls; they run inline and are checked and
audited like any other call. See [Sessions and rate limits](sessions.md).
