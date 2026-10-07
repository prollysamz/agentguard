# Quickstart

## Install

AgentGuard needs Python 3.11 or later.

```sh
pip install agentguard-oss
```

The package is `agentguard-oss`; the import is `agentguard`. Framework adapters are
optional extras: `agentguard-oss[langchain]`, `[openai-agents]`, `[adk]`, `[mcp]`, or `[all]`.

## Try the demo

```sh
agentguard demo --scripted
```

The demo gives an agent a calculator to fix. The repository's README contains a prompt
injection asking it to steal `~/.ssh/id_rsa`. AgentGuard lets it read the README, blocks
the SSH-key read and the `curl` exfiltration, allows the fix and a real unit test, and
escalates the push to `main` for approval. With [Ollama](https://ollama.com) and a Gemma
model installed, `agentguard demo` runs a live [Gemma agent](gemma.md) instead.

## Guard your first tool

Save this as `quickstart.py` and run it from an empty directory:

```python
--8<-- "examples/quickstart.py"
```

Output:

```text
hello from the workspace
Denied read_file: Policy default: deny; Sensitive credential file access
Denied run: Policy rule 2: ask; Capability baseline: 40; Approval rejected, unavailable, insufficient, or timed out
Decisions: {'allow': 1, 'ask': 1, 'deny': 1}
```

Three things happened:

1. `read_file("workspace/notes.txt")` matched the `filesystem.read` rule and ran.
2. Reading `~/.ssh/id_rsa` matched no rule (default deny) and is a credential file, which
   is always denied. The function never ran.
3. `run` is marked `ask`. No approval provider is configured, so asking means deny.

## Look at the audit log

```sh
agentguard verify-log --audit quickstart-audit.jsonl
agentguard logs --audit quickstart-audit.jsonl --decision deny
```

Every call left `proposed`, `denied` or `authorized` → `executing` → `executed` →
`observed` events, chained by SHA-256 hashes. See [Audit log](audit.md).

## Move the policy to a file

```yaml title="policy.yaml"
version: 1
defaults:
  effect: deny
rules:
  - capability: filesystem.read
    paths: ["./workspace/**"]
    effect: allow
  - capability: shell.execute
    effect: ask
```

```python
guard = Guard("policy.yaml", audit="agentguard.jsonl")
```

Check it and ask how it decides a call before running anything:

```sh
agentguard check-policy policy.yaml
agentguard explain policy.yaml shell.execute --arg cmd="git push origin main"
```

## Next steps

- [Register tools](tools.md) with any parameter names, executors and verifiers.
- Connect your framework: [LangChain/LangGraph](integrations/langchain.md),
  [OpenAI Agents SDK](integrations/openai-agents.md), [Google ADK](integrations/adk.md),
  [MCP](integrations/mcp.md).
- Add a human: [Approval](approval.md).
