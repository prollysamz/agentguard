# Approval

When a decision is `ask`, the Guard asks its approval provider. Without a provider, or
when the provider rejects, times out, fails or returns something malformed, the call is
denied. Approval can never override a deny.

AgentGuard ships two providers:

| Provider | Use it for |
| --- | --- |
| `QueueApproval` | Real deployments: approvers decide in the [dashboard](dashboard.md), Slack or your own system. Does not block the agent. Supports time-boxed grants. |
| `CLIApproval` | Local development: a prompt in the terminal running the agent. |

## Queued approval

```python
from agentguard import Guard
from agentguard.approval import ApprovalStore, QueueApproval

store = ApprovalStore("agentguard-approvals.db")
guard = Guard("policy.yaml", approval=QueueApproval(store))
```

```sh
agentguard approvers add alice                 # prints alice's token once
agentguard approvers add sam --strong          # may give strong approval
agentguard dashboard                           # http://127.0.0.1:8765
```

### The agent is not blocked

With the default `wait=0`, an `ask` call raises `ApprovalPending` immediately with a
request ID. The agent can continue with other work. When a human approves, **retrying
the same call** goes through:

```python
from agentguard import ApprovalPending

try:
    deploy(env="staging")
except ApprovalPending as pending:
    print("Waiting for", pending.request_id)   # e.g. apr_3f...
    # ...later, after approval:
    deploy(env="staging")                      # runs
```

Framework adapters return this to the model as
`{"error": "Approval pending", "request_id": ..., "next_step": "...retry the same call later"}`.

- Retrying before a decision reuses the same request; it does not create a new one.
- A recently rejected call is denied immediately instead of asking again.
- `QueueApproval(store, wait=30)` waits up to 30 seconds for a decision inside the call
  before raising `ApprovalPending`. Keep the Guard's `approval_timeout` above `wait`.
- `approval.wait_for(request_id, timeout)` and `await approval.await_decision(...)` let your
  code wait for a decision explicitly.
- Requests expire after `request_ttl` (default one hour).

### Grants: "allow this for 10 minutes"

Approving creates a grant. The approver picks its scope:

| Scope | Covers | Duration |
| --- | --- | --- |
| `once` | This exact call, one time | Must be retried within 15 minutes |
| `action` | This exact call (tool and arguments), any number of times | 1 min to 24 h |
| `tool` | Any call to this tool | 1 min to 24 h |
| `capability` | Any tool with this capability | 1 min to 24 h |

Grants apply to the same `agent_id` and environment as the request. They are checked
before asking again, never cover `deny` decisions, and cover strong-approval decisions only
if given with strong approval. Revoke one in the dashboard or with `store.revoke_grant`.

### Approvers and strong approval

Approvers authenticate with a token created by `agentguard approvers add`. Only its SHA-256
hash is stored. An approver created with `--strong` can approve requests whose risk crosses
the policy's `strong` threshold, and must re-enter their token for each such decision.

### Notifications

```python
from agentguard.approval import QueueApproval, SlackNotifier, WebhookNotifier

approval = QueueApproval(
    store,
    notifiers=[
        SlackNotifier(bot_token=..., channel="#agent-approvals",
                      dashboard_url="https://guard.internal.example"),
        WebhookNotifier("https://ops.example/hooks/agentguard", secret=...,
                        dashboard_url="https://guard.internal.example"),
    ],
)
```

**Slack.** With a bot token (`chat:write`), messages get *Approve once*, *Allow this tool
10 min* and *Reject* buttons. Enable Interactivity in the Slack app with the request URL
`<dashboard>/slack/actions`, run the dashboard with `--slack-signing-secret-env VAR`, and
link each approver to their Slack user: `agentguard approvers add alice --slack-user U0123`.
Every click is verified with Slack's signing secret. Requests that need strong approval get
a dashboard link instead of buttons. With only an incoming `webhook_url`, messages link to
the dashboard.

**Webhook.** Sends `{"type": "approval.requested", "request": {...}}` with
`X-AgentGuard-Timestamp` and `X-AgentGuard-Signature: sha256=<hmac>` over
`"<timestamp>.<body>"`. Verify it with `agentguard.approval.webhook.verify_signature`, then
decide through the dashboard API:

```sh
curl -X POST https://guard.internal.example/api/approvals/apr_3f.../decision \
  -H "Authorization: Bearer $APPROVER_TOKEN" -H "Content-Type: application/json" \
  -d '{"approve": true, "scope": "tool", "minutes": 10, "note": "release window"}'
```

Notification failures are logged and never block the agent. Arguments in notifications
are redacted.

## Terminal approval

```python
from agentguard.approval import CLIApproval

guard = Guard("policy.yaml", approval=CLIApproval(timeout=30), approval_timeout=31)
```

The operator sees the redacted action, risk score and reasons, and types `A` to approve
once or `R` to reject. It needs an interactive terminal, blocks the agent while it waits,
and does not perform strong approval: decisions that require it are denied.

## Custom providers

Any object with a `request(action, decision)` method returning an `Approval` works:

```python
from agentguard import Approval


class MyApproval:
    def request(self, action, decision):
        answer = ask_somebody(action, decision)  # your code
        return Approval(
            approved=answer.approved,
            approved_by=answer.user_id,  # required when approving
            strong=answer.reauthenticated,  # only after real reauthentication
        )
```

Rules the Guard enforces on every answer:

- `approved` must be a real `bool`; anything else is a rejection.
- An approval without `approved_by` (or with `"unknown"`) is a rejection.
- If the decision needs strong approval (`decision.strong_approval`), `strong=True` is required.
- `Approval(False, pending_id="...")` means "queued"; the call raises `ApprovalPending`.
- The provider receives a deep copy of the action; editing it cannot change what runs.
- Answers after `approval_timeout` are ignored.

Providers are trusted code. AgentGuard checks the shape of the answer, not who gave it.
