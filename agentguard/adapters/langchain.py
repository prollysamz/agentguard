"""LangChain and LangGraph tools backed by AgentGuard. Requires ``agentguard-oss[langchain]``.

The returned StructuredTool works anywhere LangChain tools do, including LangGraph's
ToolNode and prebuilt agents. Pass only the returned tool to the agent.
"""

import inspect

from langchain_core.tools import StructuredTool

from agentguard.adapters._common import describe, returning_denials


def from_guarded(guarded, *, name=None, description=None, return_denials=True):
    """Wrap a function already decorated with ``@guard.tool``."""
    func = returning_denials(guarded) if return_denials else guarded
    options = {"name": name or guarded.__name__, "description": describe(guarded, description)}
    if inspect.iscoroutinefunction(guarded):
        return StructuredTool.from_function(coroutine=func, **options)
    return StructuredTool.from_function(func=func, **options)


def guarded_tool(
    guard, function, *, capability, name=None, description=None, return_denials=True, **options
):
    """Register ``function`` with ``guard`` and return it as a LangChain StructuredTool.

    ``options`` are passed to ``guard.tool`` (executor, verifier, path_arg, ...).
    """
    guarded = guard.tool(capability=capability, name=name, **options)(function)
    return from_guarded(guarded, description=description, return_denials=return_denials)
