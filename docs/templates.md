# Policy templates

Starting points to copy and adapt. Each is checked by the test suite. Inspect any of them
with `agentguard explain` before use.

## Coding agent

Works inside `./workspace`, runs commands (pair it with an allowlisting `ShellExecutor`),
asks before deleting files, pushing, or running commands in production.

```yaml title="examples/policies/coding-agent.yaml"
--8<-- "examples/policies/coding-agent.yaml"
```

## Browsing agent

Reads an allowlist of sites, saves to `./downloads`, never sends credentials. Pair fetch
tools with `NetworkExecutor`.

```yaml title="examples/policies/browsing-agent.yaml"
--8<-- "examples/policies/browsing-agent.yaml"
```

## Support agent

Uses custom capabilities for a CRM and refunds. Replies go out to one customer at a time;
refunds need a human.

```yaml title="examples/policies/support-agent.yaml"
--8<-- "examples/policies/support-agent.yaml"
```

```sh
agentguard explain examples/policies/support-agent.yaml payments.refund --arg order_id=o-1 --env production
```
