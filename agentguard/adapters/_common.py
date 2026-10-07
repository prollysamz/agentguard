"""Shared adapter helpers. Adapters translate and dispatch; they make no security decisions."""

import functools
import inspect

from agentguard.core.decision import GuardDenied


def denial_result(exc: GuardDenied) -> dict:
    """What the model sees when AgentGuard denies a call: the reasons, so it can adapt."""
    return {"error": "Denied by AgentGuard", "reasons": list(exc.decision.reasons)}


def returning_denials(guarded, on_denied=denial_result):
    """Wrap a guarded tool so denials become a result instead of an exception.

    Only GuardDenied is converted. Other GuardErrors (a halted session, failed execution)
    still raise, so frameworks surface them as tool failures.
    """
    if inspect.iscoroutinefunction(guarded):

        @functools.wraps(guarded)
        async def wrapper(*args, **kwargs):
            try:
                return await guarded(*args, **kwargs)
            except GuardDenied as exc:
                return on_denied(exc)
    else:

        @functools.wraps(guarded)
        def wrapper(*args, **kwargs):
            try:
                return guarded(*args, **kwargs)
            except GuardDenied as exc:
                return on_denied(exc)

    # The return type changes on denial; frameworks infer only the arguments from this.
    wrapper.__signature__ = inspect.signature(guarded).replace(
        return_annotation=inspect.Signature.empty
    )
    wrapper.__annotations__ = {k: v for k, v in guarded.__annotations__.items() if k != "return"}
    return wrapper


def describe(function, description):
    return description or inspect.getdoc(function) or f"{function.__name__} (guarded by AgentGuard)"
