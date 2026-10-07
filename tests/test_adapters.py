import asyncio
import json

import pytest

from agentguard import GuardDenied
from agentguard.audit.reader import read_log


@pytest.fixture
def guard(make_guard, tmp_path):
    return make_guard(
        [
            {
                "capability": "filesystem.read",
                "paths": [str(tmp_path / "docs" / "**")],
                "effect": "allow",
            }
        ]
    )


def read_doc(path: str, max_lines: int = 10) -> str:
    """Read a documentation file."""
    return f"lines={max_lines}"


async def aread_doc(path: str) -> str:
    """Read a documentation file asynchronously."""
    return "async ok"


def denied(result):
    return isinstance(result, dict) and result["error"] == "Denied by AgentGuard"


def stages(guard):
    return [e["stage"] for e in read_log(guard.audit.path)]


# ---------------------------------------------------------------- LangChain / LangGraph


def test_langchain_tool_schema_dispatch_and_denial(guard):
    pytest.importorskip("langchain_core")
    from agentguard.adapters.langchain import guarded_tool

    tool = guarded_tool(guard, read_doc, capability="filesystem.read")
    assert tool.name == "read_doc" and tool.description == "Read a documentation file."
    assert set(tool.args) == {"path", "max_lines"}
    assert tool.invoke({"path": "docs/a.md", "max_lines": 3}) == "lines=3"
    result = tool.invoke({"path": "secrets/a.md"})
    assert denied(result) and any("Policy default: deny" in r for r in result["reasons"])
    assert stages(guard).count("observed") == 1 and "denied" in stages(guard)


def test_langchain_async_tool_and_raising_mode(guard):
    pytest.importorskip("langchain_core")
    from agentguard.adapters.langchain import guarded_tool

    tool = guarded_tool(guard, aread_doc, capability="filesystem.read")
    assert asyncio.run(tool.ainvoke({"path": "docs/a.md"})) == "async ok"
    strict = guarded_tool(
        guard, read_doc, capability="filesystem.read", name="strict", return_denials=False
    )
    with pytest.raises(GuardDenied):
        strict.invoke({"path": "secrets/a.md"})


def test_langgraph_tool_node_dispatches_through_guard(guard):
    pytest.importorskip("langgraph")
    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    from agentguard.adapters.langchain import guarded_tool

    tool = guarded_tool(guard, read_doc, capability="filesystem.read")
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([tool]))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    calls = [
        {"name": "read_doc", "args": {"path": "docs/a.md"}, "id": "1"},
        {"name": "read_doc", "args": {"path": "../outside.md"}, "id": "2"},
    ]
    messages = builder.compile().invoke({"messages": [AIMessage(content="", tool_calls=calls)]})
    allowed, blocked = messages["messages"][-2:]
    assert allowed.content == "lines=10"
    assert "Denied by AgentGuard" in blocked.content


# ---------------------------------------------------------------- OpenAI Agents SDK


def invoke_openai(tool, arguments):
    from agents.tool_context import ToolContext

    payload = json.dumps(arguments)
    context = ToolContext(
        context=None, tool_name=tool.name, tool_call_id="call_1", tool_arguments=payload
    )
    return asyncio.run(tool.on_invoke_tool(context, payload))


def test_openai_agents_tool_schema_dispatch_and_denial(guard):
    pytest.importorskip("agents")
    from agentguard.adapters.openai_agents import guarded_tool

    tool = guarded_tool(guard, read_doc, capability="filesystem.read")
    assert tool.name == "read_doc" and tool.description == "Read a documentation file."
    assert set(tool.params_json_schema["properties"]) == {"path", "max_lines"}
    assert invoke_openai(tool, {"path": "docs/a.md", "max_lines": 2}) == "lines=2"
    assert denied(invoke_openai(tool, {"path": "secrets/a.md", "max_lines": 2}))
    assert stages(guard).count("observed") == 1


def test_openai_agents_async_tool(guard):
    pytest.importorskip("agents")
    from agentguard.adapters.openai_agents import guarded_tool

    tool = guarded_tool(guard, aread_doc, capability="filesystem.read")
    assert invoke_openai(tool, {"path": "docs/a.md"}) == "async ok"


# ---------------------------------------------------------------- Google ADK


def test_adk_tool_declaration_dispatch_and_denial(guard):
    pytest.importorskip("google.adk")
    from agentguard.adapters.adk import guarded_tool

    tool = guarded_tool(guard, read_doc, capability="filesystem.read")
    declaration = tool._get_declaration().model_dump(exclude_none=True)
    assert declaration["name"] == "read_doc"
    assert declaration["description"] == "Read a documentation file."
    assert set(declaration["parameters_json_schema"]["properties"]) == {"path", "max_lines"}
    run = tool.run_async
    assert asyncio.run(run(args={"path": "docs/a.md"}, tool_context=None)) == "lines=10"
    assert denied(asyncio.run(run(args={"path": "secrets/a.md"}, tool_context=None)))
    assert stages(guard).count("observed") == 1


# ---------------------------------------------------------------- Shared behavior


def test_halted_session_still_raises_through_adapters(guard):
    pytest.importorskip("langchain_core")
    from agentguard import GuardError
    from agentguard.adapters.langchain import guarded_tool

    def broken(path: str) -> str:
        """Fails during execution."""
        raise RuntimeError("tool crashed")

    tool = guarded_tool(guard, broken, capability="filesystem.read")
    with pytest.raises(GuardError, match="session halted"):
        tool.invoke({"path": "docs/a.md"})
