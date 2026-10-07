# OpenAI Agents SDK

```sh
pip install "agentguard-oss[openai-agents]"
```

`guarded_tool` registers a function with the Guard and returns an Agents SDK
`FunctionTool`.

```python
from agents import Agent, Runner

from agentguard import Guard
from agentguard.adapters.openai_agents import guarded_tool

guard = Guard("policy.yaml", audit="agentguard.jsonl")


def fetch_page(url: str) -> str:
    """Fetch a documentation page."""
    ...


agent = Agent(
    name="Researcher",
    instructions="Answer using the documentation.",
    tools=[guarded_tool(guard, fetch_page, capability="network.request")],
)
result = Runner.run_sync(agent, "What does asyncio.TaskGroup do?")
```

## Options

| Argument | Default | Meaning |
| --- | --- | --- |
| `capability` | required | The tool's capability |
| `name`, `description` | function name, docstring | What the model sees |
| `return_denials` | `True` | Return denials as `{"error": ..., "reasons": [...]}`; `False` raises, and the SDK reports a tool error |
| `**options` | | Passed to `guard.tool`: `executor`, `verifier`, `url_arg`, ... |

Already decorated with `@guard.tool`? Use `from_guarded(guarded_function)`. Async
functions are supported.

The Agents SDK also has its own guardrails and `needs_approval`. They work alongside
AgentGuard; AgentGuard's policy, risk checks and audit apply to every call regardless.
