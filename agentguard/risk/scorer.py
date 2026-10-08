import json
import re
from dataclasses import dataclass

from agentguard.core.action import Action
from agentguard.core.context import SessionRiskContext
from agentguard.policy.matcher import resolve_path
from agentguard.risk.commands import assess as assess_command
from agentguard.risk.rules import (
    EXTERNAL_COMMAND,
    PERSISTENCE_PATH,
    PROTECTED_PUSH,
    REMOTE_PUSH,
    SENSITIVE_PATH,
)
from agentguard.risk.secrets import detect_pii, detect_secrets


@dataclass(frozen=True)
class Risk:
    score: int
    reasons: tuple[str, ...]
    hard_deny: bool = False


BASELINES = {
    "filesystem.read": 5,
    "filesystem.write": 28,
    "filesystem.delete": 65,
    "shell.execute": 40,
    "network.request": 30,
    "email.send": 55,
    "message.send": 55,
    "repository.write": 45,
}
OUTBOUND = frozenset({"network.request", "email.send", "message.send", "repository.write"})


def score(action: Action, session: SessionRiskContext, custom=None) -> Risk:
    """custom maps user-defined capability names to CapabilitySpec (risk, outbound)."""
    cap = action.capability
    spec = (custom or {}).get(cap)
    base = BASELINES[cap] if cap in BASELINES else spec.risk
    reasons = [f"Capability baseline: {base}"]
    raw = json.dumps(action.arguments)
    command = str(action.arguments.get("cmd", action.arguments.get("command", "")))
    secrets = detect_secrets(action.arguments)
    # Pushes publish repository content, so they count as outbound for taint checks.
    outbound = (
        cap in OUTBOUND
        or bool(spec and spec.outbound)
        or bool(EXTERNAL_COMMAND.search(command) or REMOTE_PUSH.search(command))
    )
    if cap.startswith("filesystem."):
        # Check the requested path and its link-resolved target.
        requested = action.arguments.get("path", "")
        resolved = resolve_path(requested, action.context.working_directory) if requested else ""
        if SENSITIVE_PATH.search(requested) or SENSITIVE_PATH.search(resolved):
            return Risk(100, ("Sensitive credential file access",), True)
        # Compare POSIX-style: C:\etc\x and /etc/x are the same location to the rules.
        posix = [re.sub(r"^[A-Za-z]:", "", p.replace("\\", "/")) for p in (requested, resolved)]
        if cap != "filesystem.read" and any(PERSISTENCE_PATH.search(p) for p in posix if p):
            base = max(base, 70)
            reasons.append("Changes a startup, hook, CI, service or log location")
    if cap in {"shell.execute", "repository.write"}:
        if SENSITIVE_PATH.search(command):
            return Risk(100, ("Command references credential files",), True)
        destructive, concerns = assess_command(command)
        if destructive:
            return Risk(100, tuple(destructive), True)
        if concerns:
            base = max(base, 70)
            reasons.extend(concerns)
        if PROTECTED_PUSH.search(command):
            base = max(base, 72)
            reasons.append("Protected branch or force push")
        elif REMOTE_PUSH.search(command):
            base = max(base, 55)
            reasons.append("Remote repository modification")
        if EXTERNAL_COMMAND.search(command):
            base = max(base, 65)
            reasons.append("External transfer command")
    if secrets and outbound:
        return Risk(100, ("Sensitive credential detected in outbound payload",), True)
    if outbound and session.sensitive_data_seen:
        return Risk(
            100, ("Outbound action after sensitive data was observed in this session",), True
        )
    if secrets:
        base += 20
        reasons.append("Sensitive data in arguments")
    personal = detect_pii(action.arguments) if outbound else set()
    if personal & {"credit_card", "ssn", "iban"}:
        base += 30
        reasons.append("Financial or government identifier in outbound payload")
    elif personal:
        base += 10
        reasons.append("Personal data in outbound payload")
    if action.context.environment == "production":
        base += 15
        reasons.append("Production environment")
    if len(session.denied_actions) >= 3:
        base += 10
        reasons.append("Repeated denied actions in session")
    if "production" in raw.lower() and "database_url" in secrets:
        base = max(base, 80)
    return Risk(min(base, 100), tuple(reasons))
