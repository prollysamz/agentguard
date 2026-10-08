# Policies

A policy is YAML, JSON or a Python dict. Load it with `Guard("policy.yaml")`,
`Guard(dict)` or `agentguard.load_policy(...)`. Invalid policies fail closed: the Guard
does not start. Unknown fields are errors, so a typo cannot silently relax a rule.

```yaml
version: 1
defaults:
  effect: deny                # allow | ask | deny (default: deny)
capabilities:                 # optional custom capabilities
  db.query:
    risk: 30
rules:
  - capability: filesystem.read
    paths: ["./workspace/**"]
    effect: allow
  - capability: network.request
    sensitive_data: [api_key, password]
    effect: deny
risk:
  ask: 51                     # risk >= ask turns allow into ask
  strong: 76                  # risk >= strong requires strong approval
  deny: 91                    # risk >= deny always denies
limits:
  max_calls_per_minute: 120
  max_argument_bytes: 65536
  max_recipients_per_action: 10
```

## Rules

| Field | Applies to | Matches when |
| --- | --- | --- |
| `capability` | all (required) | The tool's capability is this one |
| `effect` | all (required) | `allow`, `ask` or `deny` |
| `paths` | `filesystem.*` | The resolved path equals an entry, or is under a `/**` entry |
| `domains` | `network.request` | The URL host equals an entry, or is a subdomain of `*.example.com` |
| `environment` | all | The Guard's environment (`development`, `test`, `staging`, `production`) |
| `sensitive_data` | all | Arguments contain one of `api_key`, `password`, `ssh_key`, `jwt`, `database_url`, `email`, `phone`, `credit_card`, `ssn`, `iban`. See [Detection](detection.md) |

Conditions in one rule are ANDed. Values in one list are ORed.

## Precedence

1. Any matching rule with `effect: deny` wins.
2. Otherwise the **first** matching rule decides. Put narrow exceptions above broad rules.
3. Otherwise `defaults.effect` applies.

Risk is applied afterwards and can only make a decision stricter. Approval never
overrides a deny.

## Paths

- Relative patterns are resolved against the Guard's working directory.
- A pattern is an exact path or a recursive `dir/**` prefix that respects component
  boundaries (`./work/**` does not match `./workspace`).
- Arbitrary globs (`*.py`, `?`, `[...]`) are rejected when the policy loads.
- Matching uses the fully resolved target (`..`, `~` and existing links) and is
  case-insensitive on Windows.

## Domains

Exact hostnames (`docs.python.org`) or one leading wildcard (`*.github.com`, which matches
subdomains but not `github.com` itself). Ports, paths, credentials and other wildcards are
rejected at load time.

## Custom capabilities

Declare capabilities your tools need beyond the [built-in ones](concepts.md#capabilities):

```yaml
capabilities:
  crm.read:
    risk: 10
    description: Look up customers and tickets
  payments.refund:
    risk: 70
    outbound: true            # blocked after a secret appeared in the session
rules:
  - capability: crm.read
    effect: allow
  - capability: payments.refund
    effect: ask
```

```python
@guard.tool(capability="payments.refund")
def refund(order_id: str, amount_cents: int) -> str: ...
```

Names look like `area.action` (lowercase). Built-ins cannot be redefined, and rules that
name an undeclared capability fail to load. `paths` and `domains` conditions are only
available on the built-in filesystem and network capabilities.

## Limits

| Limit | Default | Effect |
| --- | --- | --- |
| `max_calls_per_minute` | 120 | Calls per minute per `rate_limit_scope`; further calls are denied |
| `max_argument_bytes` | 65536 | JSON size of one call's arguments |
| `max_recipients_per_action` | 10 | Total across all recipient fields of an email/message tool |
| `rate_limit_scope` | `session` | Who shares `max_calls_per_minute`: `session`, `agent` or `global`. See [Sessions and rate limits](sessions.md) |

## Checking and debugging

```sh
agentguard check-policy policy.yaml
agentguard explain policy.yaml filesystem.read --arg path=./workspace/../.env
```

`explain` lists every matching rule, the policy result, each risk factor and the final
decision, without running anything. See [CLI](cli.md).
