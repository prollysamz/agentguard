"""Explain how a policy decides one proposed call, without executing anything."""

from pathlib import Path

from agentguard.core.action import Action, Context
from agentguard.core.context import SessionRiskContext
from agentguard.core.decision import Effect
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.loader import load_policy
from agentguard.policy.matcher import absolute_path, matches
from agentguard.policy.schema import Policy
from agentguard.risk.scorer import Risk, score

REQUIRED_ARGUMENTS = {"network.request": "url", "shell.execute": "cmd", "repository.write": "cmd"}


def combine(policy: Policy, policy_result: Effect, risk: Risk) -> tuple[Effect, bool]:
    """Apply risk thresholds to a policy result. Returns (effect, strong approval needed)."""
    effect = policy_result
    if risk.hard_deny or risk.score >= policy.risk.deny:
        effect = Effect.DENY
    elif effect != Effect.DENY and risk.score >= policy.risk.ask:
        effect = Effect.ASK
    return effect, risk.score >= policy.risk.strong


def explain(
    policy,
    capability: str,
    arguments: dict,
    *,
    working_directory: str | None = None,
    environment: str = "development",
) -> dict:
    """Policy and deterministic risk for one call in a fresh session (no judge, no history).

    Arguments use canonical names: path, url, cmd, content, to/cc/bcc.
    """
    policy = load_policy(policy)
    if capability not in policy.all_capabilities:
        raise ValueError(f"Unknown capability {capability!r} for this policy")
    arguments = dict(arguments)
    if "command" in arguments and "cmd" not in arguments:
        arguments["cmd"] = arguments.pop("command")
    needed = "path" if capability.startswith("filesystem.") else REQUIRED_ARGUMENTS.get(capability)
    if needed and not isinstance(arguments.get(needed), str):
        raise ValueError(f"{capability} needs a {needed} argument, e.g. --arg {needed}=...")
    context = Context(
        working_directory=str(Path(working_directory or Path.cwd()).resolve(strict=True)),
        environment=environment,
    )
    if needed == "path":
        arguments["path"] = absolute_path(arguments["path"], context.working_directory)
    action = Action(
        agent_id="explain",
        session_id="explain",
        tool="explain",
        capability=capability,
        arguments=arguments,
        context=context,
    )
    policy_result, policy_reason = PolicyEngine(policy).evaluate(action)
    risk = score(action, SessionRiskContext(), policy.capabilities)
    effect, strong = combine(policy, policy_result, risk)
    return {
        "capability": capability,
        "arguments": arguments,
        "environment": environment,
        "matched_rules": [
            {"rule": index, **rule.model_dump(mode="json", exclude_none=True)}
            for index, rule in enumerate(policy.rules, 1)
            if matches(rule, action)
        ],
        "policy_result": policy_result.value,
        "policy_reason": policy_reason,
        "risk_score": risk.score,
        "risk_reasons": list(risk.reasons),
        "hard_deny": risk.hard_deny,
        "decision": effect.value,
        "strong_approval": strong and effect == Effect.ASK,
        "thresholds": policy.risk.model_dump(),
    }
