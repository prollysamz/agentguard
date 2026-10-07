# LangChain and LangGraph

```sh
pip install "agentguard-oss[langchain]" langgraph
```

`guarded_tool` registers a function with the Guard and returns a LangChain
`StructuredTool`. It works anywhere LangChain tools do, including LangGraph's `ToolNode`
and prebuilt agents.

```python
from agentguard import Guard
from agentguard.adapters.langchain import guarded_tool

guard = Guard("policy.yaml", audit="agentguard.jsonl")


def read_file(path: str) -> str:
    """Read a UTF-8 text file from the workspace."""
    with open(path, encoding="utf-8") as f:
        return f.read()


read_tool = guarded_tool(guard, read_file, capability="filesystem.read")
```

With LangGraph:

```python
from langgraph.prebuilt import ToolNode

tools = ToolNode([read_tool])        # or create_react_agent(model, [read_tool])
```

## Options

| Argument | Default | Meaning |
| --- | --- | --- |
| `capability` | required | The tool's capability |
| `name`, `description` | function name, docstring | What the model sees |
| `return_denials` | `True` | Return denials to the model as `{"error": ..., "reasons": [...]}`; `False` raises `GuardDenied` |
| `**options` | | Passed to `guard.tool`: `executor`, `verifier`, `path_arg`, ... |

Already decorated with `@guard.tool`? Use `from_guarded(guarded_function)`.

Async functions become async tools (`ainvoke`). A halted session or failed execution still
raises, so LangChain reports a tool failure.

!!! warning
    Give the agent only the returned tool. If the raw function is also available, the agent
    can call it without AgentGuard.
