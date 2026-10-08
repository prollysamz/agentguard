"""Credential and personal-data detection and redaction.

Credentials come from three sources: the maintained gitleaks ruleset (``rulesets``), a few
AgentGuard patterns for formats policies name directly (private keys, JWTs, connection
strings, ``password=...`` pairs), and secret-looking field names. Personal data comes from
``pii``. Detection walks nested values once, scanning each string and each
``key: value`` pair so rules that need context still apply.
"""

import re
from typing import Any

from agentguard.risk.pii import REDACTED as REDACTED_PII
from agentguard.risk.pii import find_pii
from agentguard.risk.rulesets import find_secrets

PATTERNS = {
    "api_key": re.compile(
        # AWS and most providers come from gitleaks; these cover shorter test-style tokens.
        r"(?:(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})"
    ),
    "ssh_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?"
        r"(?:-----END [^-]*PRIVATE KEY-----|$)"
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "password": re.compile(
        r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*[\"']?[^\s\"',;}]+"
    ),
    "database_url": re.compile(
        r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+"
    ),
}
SECRET_FIELDS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|credential)"
)
CREDENTIALS = frozenset({"api_key", "ssh_key", "jwt", "password", "database_url"})
PII = frozenset({"email", "phone", "credit_card", "ssn", "iban"})


def _strings(value, key=None):
    """Yield (text, field_name) for every string in a nested value, plus key: value lines."""
    if isinstance(value, str):
        yield value, key
        if key is not None:
            yield f'{key}: "{value}"', key
    elif isinstance(value, dict):
        for k, item in value.items():
            yield from _strings(item, str(k))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _strings(item, key)
    elif value is not None and not isinstance(value, bool | int | float):
        yield str(value), key


def _field_secrets(value):
    found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_FIELDS.search(str(key)) and item:
                found.add("api_key" if "key" in str(key).lower() else "password")
            found |= _field_secrets(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            found |= _field_secrets(item)
    return found


def _text_secrets(text):
    found = {name for name, pattern in PATTERNS.items() if pattern.search(text)}
    return found | {finding.category for finding in find_secrets(text)}


def detect_secrets(value: Any) -> set[str]:
    """Credential categories in ``value``: api_key, ssh_key, jwt, password, database_url."""
    found = _field_secrets(value)
    for text, _ in _strings(value):
        found |= _text_secrets(text)
    return found


def detect_pii(value: Any) -> set[str]:
    """Personal-data categories in ``value``: email, phone, credit_card, ssn, iban."""
    return {category for text, _ in _strings(value) for category, _, _ in find_pii(text)}


def detect_sensitive(value: Any) -> set[str]:
    return detect_secrets(value) | detect_pii(value)


def _redact_text(text):
    spans = [(m.start(), m.end(), name) for name, p in PATTERNS.items() for m in p.finditer(text)]
    spans += [(f.start, f.end, f.category) for f in find_secrets(text)]
    spans += [(s, e, c) for c, s, e in find_pii(text) if c in REDACTED_PII]
    pieces, cursor = [], 0
    for start, end, name in sorted(spans):
        if end <= cursor:
            continue
        if start < cursor:  # Overlapping finding: extend the current redaction.
            pieces[-1] = pieces[-1]
            cursor = end
            continue
        pieces.append(text[cursor:start])
        pieces.append(f"[REDACTED:{name}]")
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def redact(value: Any) -> Any:
    """A copy with credentials and financial/government identifiers replaced, and control
    characters escaped for safe display."""
    if isinstance(value, dict):
        return {
            str(k): "[REDACTED]" if SECRET_FIELDS.search(str(k)) else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = _redact_text(value)
        return "".join(c if ord(c) >= 32 and ord(c) != 127 else f"\\u{ord(c):04x}" for c in value)
    return value
