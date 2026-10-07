# Google ADK

```sh
pip install "agentguard-oss[adk]"
```

`guarded_tool` registers a function with the Guard and returns an ADK `FunctionTool`. ADK
builds the declaration from the function's signature and docstring, which the guarded
wrapper preserves.

```python
from google.adk.agents import Agent

from agentguard import Guard
from agentguard.adapters.adk import guarded_tool

guard = Guard("policy.yaml", audit="agentguard.jsonl")


def lookup_order(order_id: str) -> dict:
    """Look up an order by ID."""
    ...


agent = Agent(
    name="support",
    model="gemini-2.5-flash",  # or a Gemma model served for ADK
    instruction="Help customers with their orders.",
    tools=[guarded_tool(guard, lookup_order, capability="crm.read")],
)
```

`crm.read` is a [custom capability](../policy.md#custom-capabilities); declare it in the
policy.

## Options

| Argument | Default | Meaning |
| --- | --- | --- |
| `capability` | required | The tool's capability |
| `name` | function name | Tool name |
| `return_denials` | `True` | Return denials as `{"error": ..., "reasons": [...]}`, ADK's usual error shape |
| `**options` | | Passed to `guard.tool` |

Already decorated with `@guard.tool`? Use `from_guarded(guarded_function)`.
