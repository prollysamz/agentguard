# Plain Python

No framework needed. Decorate tools and call them, or dispatch by name from your own agent
loop:

```python
from agentguard import Guard, GuardDenied

guard = Guard("policy.yaml", audit="agentguard.jsonl")

@guard.tool(capability="filesystem.read")
def read_file(path: str) -> str:
    """Read a UTF-8 text file."""
    ...

# Your agent loop: the model returns a tool name and JSON arguments.
for step in model_steps():
    try:
        result = guard.call(step.tool, step.arguments)
    except GuardDenied as exc:
        result = {"error": "denied", "reasons": list(exc.decision.reasons)}
    send_to_model(result)
```

`await guard.acall(name, arguments)` is the async equivalent. `guard.tools` lists
registered names for the model's tool list.

`GuardMiddleware` wraps the same calls for code that expects an `invoke`/`ainvoke` object:

```python
from agentguard.adapters.python import GuardMiddleware

middleware = GuardMiddleware(guard)
middleware.invoke("read_file", {"path": "notes.txt"})
```

The Gemma demo agent (`agentguard/demo/gemma_agent.py`) is a complete example of a small
agent loop built this way, including a schema that restricts the model to `guard.tools`.
