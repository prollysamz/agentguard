# Approval

When a decision is `ask`, the Guard asks its approval provider. Without a provider, or
when the provider rejects, times out, fails or returns something malformed, the call is
denied. Approval can never override a deny.

## Terminal approval

```python
from agentguard.approval import CLIApproval

guard = Guard("policy.yaml", approval=CLIApproval(timeout=30), approval_timeout=31)
```

The operator sees the redacted action, risk score and reasons, and presses `A` to approve
once or `R` to reject. Set `approval_timeout` slightly above the provider's own timeout so
a last-second answer is not discarded. CLI approval needs an interactive terminal and does
not perform strong approval: decisions that require it are denied.

## Custom providers

Any object with a `request(action, decision)` method returning an `Approval` works:

```python
from agentguard import Approval

class SlackApproval:
    def request(self, action, decision):
        answer = post_and_wait(action, decision)          # your code
        return Approval(
            approved=answer.approved,
            approved_by=answer.user_id,                   # required when approving
            strong=answer.reauthenticated,                # only after real reauthentication
        )
```

Rules the Guard enforces on every answer:

- `approved` must be a real `bool`; anything else is a rejection.
- An approval without `approved_by` (or with `"unknown"`) is a rejection.
- If the decision needs strong approval (`decision.strong_approval`), `strong=True` is required.
- The provider receives a deep copy of the action; editing it cannot change what runs.
- Answers after `approval_timeout` are ignored. Providers should stop their own pending
  work when they time out.

AgentGuard does not authenticate the approver. A provider is trusted code and is
responsible for verifying who approved. There are no session-wide grants: each action is
approved once.
