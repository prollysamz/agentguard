"""Secret detection with the gitleaks ruleset (vendored in ``risk/data/gitleaks.toml``).

Rules run on RE2 (``google-re2``), the engine they are written for, so matching is linear
time even on attacker-controlled text such as fetched pages. Each rule's keywords
prefilter the text, and entropy thresholds, allowlists and stopwords apply as in
gitleaks. If RE2 is unavailable, rules are translated to Python ``re`` and text is capped
to limit backtracking cost.
"""

import math
import tomllib
import warnings
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

try:
    import re2 as engine

    RE2 = True
except ImportError:  # pragma: no cover - exercised only without google-re2
    import re as engine

    RE2 = False

# Larger texts are scanned in overlapping windows so a long result cannot stall the agent.
WINDOW = 1_000_000
OVERLAP = 4096
FALLBACK_LIMIT = 200_000

CATEGORIES = {"private-key": "ssh_key", "jwt": "jwt", "jwt-base64": "jwt"}


@dataclass(frozen=True)
class SecretRule:
    id: str
    category: str
    pattern: object
    keywords: tuple
    entropy: float | None
    secret_group: int
    allowlists: tuple  # (target, regexes, stopwords)


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str
    start: int
    end: int


def _compile(pattern):
    if not RE2:
        pattern = pattern.replace(r"\z", r"\Z")
        if "(?i)" in pattern[1:]:
            pattern = "(?i)" + pattern.replace("(?i)", "")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        return engine.compile(pattern)


def _allowlist(entry):
    return (
        entry.get("regexTarget", "secret"),
        tuple(_compile(r) for r in entry.get("regexes", [])),
        tuple(s.lower() for s in entry.get("stopwords", [])),
    )


@lru_cache(maxsize=1)
def load_rules():
    """(rules, global allowlist) from the vendored gitleaks configuration."""
    text = files("agentguard.risk").joinpath("data", "gitleaks.toml").read_text(encoding="utf-8")
    config = tomllib.loads(text)
    rules = tuple(
        SecretRule(
            id=rule["id"],
            category=CATEGORIES.get(rule["id"], "api_key"),
            pattern=_compile(rule["regex"]),
            keywords=tuple(k.lower() for k in rule.get("keywords", [])),
            entropy=rule.get("entropy"),
            secret_group=rule.get("secretGroup", 0),
            allowlists=tuple(_allowlist(a) for a in rule.get("allowlists", [])),
        )
        for rule in config["rules"]
        if "regex" in rule
    )
    return rules, _allowlist(config.get("allowlist", {}))


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def _secret_span(match, group):
    if group and group <= match.re.groups and match.group(group):
        return match.span(group)
    for index in range(1, match.re.groups + 1):  # gitleaks: first non-empty group.
        if match.group(index):
            return match.span(index)
    return match.span(0)


def _allowed(text, match, span, lists):
    secret = text[span[0] : span[1]]
    lowered = secret.lower()
    for target, regexes, stopwords in lists:
        if any(word in lowered for word in stopwords):
            return True
        if target == "match":
            subject = match.group(0)
        elif target == "line":
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            subject = text[start : end if end != -1 else len(text)]
        else:
            subject = secret
        if any(regex.search(subject) for regex in regexes):
            return True
    return False


def _scan(text, offset, rules, global_list):
    lowered = text.lower()
    for rule in rules:
        if rule.keywords and not any(keyword in lowered for keyword in rule.keywords):
            continue
        for match in rule.pattern.finditer(text):
            span = _secret_span(match, rule.secret_group)
            secret = text[span[0] : span[1]]
            if rule.entropy and shannon_entropy(secret) < rule.entropy:
                continue
            if _allowed(text, match, span, (*rule.allowlists, global_list)):
                continue
            yield Finding(rule.id, rule.category, span[0] + offset, span[1] + offset)


def find_secrets(text):
    """Every secret the ruleset finds in ``text``, with positions for redaction."""
    if not text:
        return []
    rules, global_list = load_rules()
    if not RE2:
        text = text[:FALLBACK_LIMIT]
    findings, start = {}, 0
    while True:
        window = text[start : start + WINDOW]
        for finding in _scan(window, start, rules, global_list):
            findings[(finding.rule, finding.start, finding.end)] = finding
        if start + WINDOW >= len(text):
            break
        start += WINDOW - OVERLAP
    return sorted(findings.values(), key=lambda f: (f.start, f.end))
