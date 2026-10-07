"""Google Agent Development Kit (ADK) tools backed by AgentGuard.

Requires ``agentguard-oss[adk]``. Pass only the returned FunctionTool to ``Agent(tools=[...])``.
ADK builds the declaration from the function's signature and docstring.
"""

from google.adk.tools import FunctionTool

from agentguard.adapters._common import returning_denials


def from_guarded(guarded, *, return_denials=True) -> FunctionTool:
    """Wrap a function already decorated with ``@guard.tool``."""
    return FunctionTool(returning_denials(guarded) if return_denials else guarded)


def guarded_tool(guard, function, *, capability, name=None, return_denials=True, **options):
    """Register ``function`` with ``guard`` and return it as an ADK FunctionTool.

    ``options`` are passed to ``guard.tool`` (executor, verifier, path_arg, ...).
    """
    guarded = guard.tool(capability=capability, name=name, **options)(function)
    return from_guarded(guarded, return_denials=return_denials)
