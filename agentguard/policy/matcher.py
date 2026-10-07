import os
from pathlib import Path
from urllib.parse import urlsplit

from agentguard.core.action import Action
from agentguard.policy.schema import Rule
from agentguard.risk.secrets import detect_secrets


def resolve_path(path: str, cwd: str) -> str:
    """Absolute resolved path with its original case, used for execution."""
    if not path or "\x00" in path:
        raise ValueError("Invalid path")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    return str(candidate.resolve())


def canonical_path(path: str, cwd: str) -> str:
    """Case-folded, slash-normalized form, used only for matching."""
    return os.path.normcase(resolve_path(path, cwd)).replace("\\", "/")


def path_matches(path: str, pattern: str, cwd: str) -> bool:
    # Recursive patterns match descendants on component boundaries, never sibling prefixes.
    if pattern.replace("\\", "/").endswith("/**"):
        root = canonical_path(pattern[:-3], cwd).rstrip("/")
        return path == root or path.startswith(root + "/")
    if "*" in pattern or "?" in pattern or "[" in pattern:
        # Intentionally unsupported: arbitrary globs have surprising traversal semantics.
        return False
    return path == canonical_path(pattern, cwd)


def domain_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return host == pattern


def matches(rule: Rule, action: Action) -> bool:
    if rule.capability != action.capability:
        return False
    if rule.environment and rule.environment != action.context.environment:
        return False
    if rule.paths:
        path = canonical_path(action.arguments["path"], action.context.working_directory)
        if not any(path_matches(path, p, action.context.working_directory) for p in rule.paths):
            return False
    if rule.domains:
        host = urlsplit(action.arguments["url"]).hostname or ""
        if not any(domain_matches(host, d) for d in rule.domains):
            return False
    if rule.sensitive_data and not set(rule.sensitive_data) & detect_secrets(action.arguments):
        return False
    return True
