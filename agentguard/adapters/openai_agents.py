"""OpenAI Agents SDK tools backed by AgentGuard. Requires ``agentguard-oss[openai-agents]``.

Pass only the returned FunctionTool to ``Agent(tools=[...])``.
"""

from agents import FunctionTool, function_tool

from agentguard.adapters._common import describe, returning_denials


def from_guarded(guarded, *, name=None, description=None, return_denials=True) -> FunctionTool:
    """Wrap a function already decorated with ``@guard.tool``."""
    func = returning_denials(guarded) if return_denials else guarded
    return function_tool(
        func,
        name_override=name or guarded.__name__,
        description_override=describe(guarded, description),
    )


def guarded_tool(
    guard, function, *, capability, name=None, description=None, return_denials=True, **options
) -> FunctionTool:
    """Register ``function`` with ``guard`` and return it as an Agents SDK FunctionTool.

    ``options`` are passed to ``guard.tool`` (executor, verifier, path_arg, ...).
    """
    guarded = guard.tool(capability=capability, name=name, **options)(function)
    return from_guarded(guarded, description=description, return_denials=return_denials)
