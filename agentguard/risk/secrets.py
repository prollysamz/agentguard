import json
import re
from typing import Any

PATTERNS = {
    "api_key": re.compile(
        r"(?:AKIA[0-9A-Z]{16}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})"
    ),
    "ssh_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)"
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


def detect_secrets(value: Any) -> set[str]:
    raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=True, default=str)
    found = {name for name, pattern in PATTERNS.items() if pattern.search(raw)}
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_FIELDS.search(str(key)) and item:
                found.add("api_key" if "key" in str(key).lower() else "password")
            found.update(detect_secrets(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.update(detect_secrets(item))
    return found


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(k): "[REDACTED]" if SECRET_FIELDS.search(str(k)) else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for name, pattern in PATTERNS.items():
            value = pattern.sub("[REDACTED:" + name + "]", value)
        # Escape terminal control characters in audit and approval displays.
        return "".join(c if ord(c) >= 32 and ord(c) != 127 else f"\\u{ord(c):04x}" for c in value)
    return value
