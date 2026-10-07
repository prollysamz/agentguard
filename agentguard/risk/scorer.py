import json
from dataclasses import dataclass

from agentguard.core.action import Action
from agentguard.core.context import SessionRiskContext
from agentguard.risk.rules import (
    DANGEROUS_COMMANDS,
    EXTERNAL_COMMAND,
    PROTECTED_PUSH,
    REMOTE_PUSH,
    SENSITIVE_PATH,
)
from agentguard.risk.secrets import detect_secrets


@dataclass(frozen=True)
class Risk:
    score: int
    reasons: tuple[str, ...]
    hard_deny: bool = False


def score(action: Action, session: SessionRiskContext) -> Risk:
    cap = action.capability
    base = {
        "filesystem.read": 5,
        "filesystem.write": 28,
        "filesystem.delete": 65,
        "shell.execute": 40,
        "network.request": 30,
        "email.send": 55,
        "message.send": 55,
        "repository.write": 45,
    }[cap]
    reasons = [f"Capability baseline: {base}"]
    raw = json.dumps(action.arguments)
    command = str(action.arguments.get("cmd", action.arguments.get("command", "")))
    secrets = detect_secrets(action.arguments)
    # Pushes publish repository content, so they count as outbound for taint checks.
    outbound = cap in {"network.request", "email.send", "message.send", "repository.write"} or bool(
        EXTERNAL_COMMAND.search(command) or REMOTE_PUSH.search(command)
    )
    if cap.startswith("filesystem.") and SENSITIVE_PATH.search(action.arguments.get("path", "")):
        return Risk(100, ("Sensitive credential file access",), True)
    if cap in {"shell.execute", "repository.write"}:
        if SENSITIVE_PATH.search(command):
            return Risk(100, ("Command references credential files",), True)
        for pattern, reason in DANGEROUS_COMMANDS:
            if pattern.search(command):
                return Risk(100, (reason,), True)
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
    if action.context.environment == "production":
        base += 15
        reasons.append("Production environment")
    if len(session.denied_actions) >= 3:
        base += 10
        reasons.append("Repeated denied actions in session")
    if "production" in raw.lower() and "database_url" in secrets:
        base = max(base, 80)
    return Risk(min(base, 100), tuple(reasons))
