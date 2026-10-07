# CLI

Installed as `agentguard` (also `python -m agentguard`).

## check-policy

```sh
agentguard check-policy policy.yaml
```

Validates a policy and prints a summary (rules, default, custom capabilities, thresholds,
limits). On failure it prints each error with its location, such as
`rules.0.effect: Input should be 'allow', 'ask' or 'deny'`, and exits with status 1.

## explain

```sh
agentguard explain POLICY CAPABILITY [--arg NAME=VALUE ...] [--cwd DIR] [--env ENV] [--json]
```

Shows how the policy decides one call, without executing anything:

```text
$ agentguard explain examples/policy.yaml shell.execute --arg cmd="git push origin main" --env production
Decision: ASK (strong approval required)
Policy: ask (Policy rule 5: ask)
  matches rule 5: ask when {"environment": "production"}
Risk: 87/100
  Capability baseline: 40
  Protected branch or force push
  Production environment
Thresholds: ask 51, strong approval 76, deny 91
```

- Use canonical argument names: `path`, `url`, `cmd`, `content`, `to`, `cc`, `bcc`.
- `VALUE` is parsed as JSON when possible (`--arg to='["a@x.test"]'`), otherwise a string.
- Relative paths resolve against `--cwd` (default: the current directory).
- It evaluates a fresh session without a judge. Session history (taint, repeated denials)
  can make a real call stricter.

## demo

```sh
agentguard demo [--model MODEL | --scripted] [--judge] [--interactive] [--audit FILE]
```

Runs the prompt-injection demo in a temporary directory. See [Gemma](gemma.md).

## logs, inspect, verify-log, report

```sh
agentguard logs --audit FILE [--decision allow|ask|deny] [--risk low|medium|high|critical]
agentguard inspect EVENT_ID --audit FILE
agentguard verify-log --audit FILE [--key-env VAR]
agentguard report --audit FILE [--dry-run-only] [--json]
```

Each verifies every segment of the hash chain and the checkpoint before printing.
`--key-env` names an environment variable holding the signing key, and also verifies event
signatures. `report` groups calls that were asked about or denied by tool and reason. Risk
bands: low 0–25, medium 26–50, high 51–90, critical 91–100. See [Audit log](audit.md).

## approvers, approvals

```sh
agentguard approvers add NAME [--slack-user U0123] [--strong] [--store FILE]
agentguard approvers list [--store FILE]
agentguard approvers remove NAME [--store FILE]
agentguard approvals list [--status pending|approved|rejected|expired] [--store FILE]
```

`add` prints the approver's token once. The default store is `agentguard-approvals.db`.
See [Approval](approval.md).

## dashboard

```sh
agentguard dashboard [--audit FILE] [--store FILE] [--host 127.0.0.1] [--port 8765]
                     [--audit-key-env VAR] [--slack-signing-secret-env VAR] [--secure-cookies]
```

Serves the approvals, audit log and policy report UI. Needs `agentguard-oss[dashboard]`.
See [Dashboard](dashboard.md).
