# AgentGuard

**Let agents act. Keep humans in control.**

AgentGuard is an open-source Python SDK that sits between an AI agent and its tools.
Every tool call the agent proposes is validated, checked against a policy, scored for
risk, optionally reviewed by a local Gemma model, sent to a human when needed, run
through a restricted executor, verified, and written to a tamper-evident audit log.

```sh
pip install agentguard-oss
```

```python
from agentguard import Guard

guard = Guard("policy.yaml", audit="agentguard.jsonl")

@guard.tool(capability="filesystem.read")
def read_file(path: str) -> str:
    """Read a UTF-8 text file."""
    return open(path, encoding="utf-8").read()

# Give the agent read_file. read_file("~/.ssh/id_rsa") raises GuardDenied
# before the function body runs, and the attempt is in the audit log.
```

## What it does

| Control | What you get |
| --- | --- |
| **Policy as code** | YAML rules allow, ask or deny by capability, path, domain, environment and secrets in arguments. Explicit denies always win. |
| **Risk checks** | Explainable 0–100 scores. Credential files, destructive commands and exfiltration after a secret was seen are always denied. |
| **Human approval** | Risky actions go to a person in the dashboard, Slack or your own system, without blocking the agent. Grants like "allow this tool for 10 minutes". No answer means deny. |
| **Controlled execution** | Executors confine file access to a root, run only allowlisted commands, and allow only HTTPS GETs to listed domains. |
| **Verification** | Before/after hashes catch tools that change files they were not asked to. |
| **Audit** | Every stage of every call in a signed SHA-256 hash chain with rotation, exported to OpenTelemetry or your SIEM. |
| **Dashboard** | Approval queue, audit log viewer and a dry-run policy report. |
| **Multi-agent** | Parallel per-agent sessions and rate limits shared through Redis. |
| **Integrations** | LangChain, LangGraph, OpenAI Agents SDK, Google ADK, MCP, plain Python. |
| **Gemma** | A local Gemma agent for the demo, and an optional Gemma security judge that can only add caution. |

## Where to go next

- [Quickstart](quickstart.md): guard your first tool in five minutes.
- [Concepts](concepts.md): the pipeline, trust boundary and how decisions are made.
- [Integrations](integrations/langchain.md): plug into your agent framework.
- [Policy templates](templates.md): starting points for coding, browsing and support agents.
- [Threat model](security.md): what AgentGuard protects against, and what it does not.

!!! warning "Status"
    AgentGuard is alpha software (0.x) and has not had an independent security audit.
    It is an interception layer, not an OS sandbox: an agent that also has unguarded
    tools, raw shell or Python access can bypass it. Read the
    [threat model](security.md) before guarding privileged tools.
