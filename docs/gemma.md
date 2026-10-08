# Gemma agent and judge

AgentGuard uses [Gemma](https://ai.google.dev/gemma) running locally through
[Ollama](https://ollama.com) in two roles: as the agent in the demo, and as an optional
semantic security judge.

```sh
ollama pull gemma3:4b
agentguard demo --interactive           # Gemma agent, approve the push yourself
agentguard demo --judge --interactive   # plus the Gemma judge
agentguard demo --model qwen3:8b        # any Ollama model
agentguard demo --scripted              # offline, reproducible
```

`agentguard demo` detects installed models (preferring `gemma3:4b`) and falls back to the
scripted run if Ollama or Gemma is unavailable.

## The demo agent

The agent sees only guarded tools. Its replies are constrained to the registered tool
names, it is shown AgentGuard's denial reasons, and it is stopped from repeating a denied
action. With `gemma3:4b` it reads the injected README, ignores it, fixes the bug, reruns the
failing test until it passes, and requests the push, which is escalated for approval.
Small models are not reliable agents; the audit log, not the model's summary, is the
record of what happened.

## The judge

```python
from agentguard.risk.gemma_judge import GemmaJudge

judge = GemmaJudge(
    model="gemma3:4b",
    guidance="run_tests runs the unit tests; the workspace is disposable.",
    capabilities={"shell.execute", "network.request", "message.send"},
)
guard = Guard("policy.yaml", judge=judge)
```

| Parameter | Meaning |
| --- | --- |
| `model`, `endpoint`, `timeout` | Local Ollama only (`http://localhost`/`127.0.0.1`/`::1`); default timeout 60s |
| `guidance` | Trusted deployment context added to the judge's prompt |
| `capabilities` | Review only these capabilities; `None` reviews all |

How its answer is used:

- It can only raise risk. A lower score never lowers the deterministic one.
- A score at or above the policy's `deny` threshold denies.
- A `deny` flag with a lower score escalates to human approval, because small models
  produce false positives.
- It is skipped when the policy denies or a hard-deny rule already fired.
- Timeouts, invalid output and service errors keep the deterministic decision.
- It receives redacted action data.

Any object with `evaluate(action) -> Risk` (and optionally a `capabilities` set) can be a
judge.

!!! note "Measured behavior"
    On the [benchmark](benchmarks.md), `gemma3:4b` as a judge caught 85% of unsafe actions
    but flagged 37% of safe ones (writing tests, `npm ci`, `docker build`), and missed every
    credential-file read, which the deterministic rules catch. `qwen3:8b` caught 88% with no
    false positives. With temperature 0 and the benchmark prompt, both were stable across
    repeated runs. Inside the demo's agent loop, with a different prompt and context,
    `gemma3:4b` once scored the same code edit 28 and then 75, which is why the demo limits
    the judge to shell, network and messages. Treat a small judge as an extra signal for a
    human, not a gatekeeper, and measure your own model with `agentguard judge-bench`.
