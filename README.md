# AgentGuard

**Let agents act. Keep humans in control.**

[![CI](https://github.com/prollysamz/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/prollysamz/agentguard/actions/workflows/ci.yml)
[![Docs](https://github.com/prollysamz/agentguard/actions/workflows/docs.yml/badge.svg)](https://prollysamz.github.io/agentguard/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)

AgentGuard is an open-source Python SDK that sits between an AI agent and its tools.
Every tool call is validated, checked against a policy, scored for risk, optionally
reviewed by a local **Gemma** model, sent to a human when needed, run through a
restricted executor, verified, and written to a tamper-evident audit log.

**[Documentation](https://prollysamz.github.io/agentguard/)** ·
[Quickstart](https://prollysamz.github.io/agentguard/quickstart/) ·
[Integrations](https://prollysamz.github.io/agentguard/integrations/langchain/) ·
[Threat model](THREAT_MODEL.md) · [Changelog](CHANGELOG.md)

## See it work

```sh
pip install agentguard-oss
agentguard demo --scripted
```

An agent is asked to fix a calculator. The repository's README hides a prompt injection
telling it to read `~/.ssh/id_rsa` and upload it. AgentGuard lets the agent read the
README, **blocks** the SSH-key read and the `curl` exfiltration, **allows** the fix and a
real unit test, and **escalates** the push to `main` for human approval.

With [Ollama](https://ollama.com) and `ollama pull gemma3:4b`, plain `agentguard demo`
runs a live **Gemma agent** against the same trap, and `--judge` adds a Gemma security
reviewer. Add `--interactive` to approve the push yourself. See
[Gemma agent and judge](https://prollysamz.github.io/agentguard/gemma/).

## Guard a tool

```python
from pathlib import Path

from agentguard import Guard

guard = Guard(
    {
        "version": 1,
        "defaults": {"effect": "deny"},
        "rules": [
            {"capability": "filesystem.read", "paths": ["./workspace/**"], "effect": "allow"},
            {"capability": "shell.execute", "effect": "ask"},
        ],
    },
    audit="agentguard.jsonl",
)


@guard.tool(capability="filesystem.read")
def read_file(path: str) -> str:
    """Read a UTF-8 text file."""
    return Path(path).read_text(encoding="utf-8")


# Give the agent read_file, never the raw function.
# read_file("~/.ssh/id_rsa") raises GuardDenied before the function body runs.
```

Then check the policy, ask how it decides a call, and verify the log:

```sh
agentguard check-policy policy.yaml
agentguard explain policy.yaml shell.execute --arg cmd="git push origin main"
agentguard verify-log --audit agentguard.jsonl
```

## Use it with your framework

```sh
pip install "agentguard-oss[langchain]"   # also [openai-agents], [adk], [mcp], [all]
```

```python
from agentguard.adapters.langchain import guarded_tool        # LangChain / LangGraph
# from agentguard.adapters.openai_agents import guarded_tool  # OpenAI Agents SDK
# from agentguard.adapters.adk import guarded_tool            # Google ADK


def read_notes(path: str) -> str:
    """Read a notes file."""
    return Path(path).read_text(encoding="utf-8")


notes_tool = guarded_tool(guard, read_notes, capability="filesystem.read")
```

Denials go back to the model with AgentGuard's reasons so the agent can adapt. MCP
servers use `agentguard.adapters.mcp.register_tool`; any other loop can call
`guard.call(name, arguments)`.

## What you get

| Control | Details |
| --- | --- |
| **Policy as code** | YAML allow / ask / deny rules by capability, path, domain, environment and secrets. Explicit denies win. [Custom capabilities](https://prollysamz.github.io/agentguard/policy/#custom-capabilities) like `db.query` or `payments.refund`. |
| **Risk checks** | Explainable 0–100 scores. Credential files, destructive commands and exfiltration after a secret was seen are always denied. |
| **Human approval** | Risky calls wait for a person. No answer, a timeout or a broken approver means deny. |
| **Controlled execution** | Executors confine files to a root and reject links, run only allowlisted commands, and allow only HTTPS GETs to listed domains. |
| **Verification** | Before/after hashes catch tools that change files they were not asked to. |
| **Audit** | Every stage of every call in a SHA-256 hash chain, with `logs`, `inspect` and `verify-log`. |
| **Gemma** | A local Gemma agent for the demo, and an optional judge that can only add caution. |

Starter policies for [coding, browsing and support agents](examples/policies/) are in
`examples/policies/`.

## Status

AgentGuard 0.2 is alpha and has not had an independent security audit. It is an
interception layer for cooperative applications, not an OS sandbox: an agent that also has
unguarded tools, a raw shell or Python `exec` can go around it. Read the
[threat model](THREAT_MODEL.md) before guarding privileged tools, and report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Develop

```sh
git clone https://github.com/prollysamz/agentguard.git
cd agentguard
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev,all,docs]"
python -m pytest -q
python -m ruff check .
mkdocs serve
```

CI runs the tests on Linux and Windows with Python 3.11 and 3.12. See
[CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed.
