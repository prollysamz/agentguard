import json
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentguard import GuardDenied
from agentguard.audit.reader import read_log
from agentguard.risk.pii import find_pii, luhn
from agentguard.risk.rulesets import RE2, find_secrets, load_rules
from agentguard.risk.secrets import detect_pii, detect_secrets, redact

SLACK = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
STRIPE = "sk_live_" + "51HxYzAbCdEfGhIjKlMnOpQr"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def test_vendored_ruleset_loads_on_re2():
    rules, _ = load_rules()
    assert len(rules) > 200 and RE2
    assert {r.id for r in rules} >= {"github-pat", "slack-bot-token", "aws-access-token"}


@pytest.mark.parametrize(
    "text,rule",
    [
        (f"token: {GITHUB}", "github-pat"),
        (f"SLACK={SLACK}", "slack-bot-token"),
        (f"stripe key {STRIPE}", "stripe-access-token"),
        ("aws_access_key_id = AKIA4HKQ2J7XOTVBHJ3U", "aws-access-token"),
        ('api_key = "Zx9qL2mN7vB4cR8tY1wE6uI3oP5aS0dF"', "generic-api-key"),
    ],
)
def test_gitleaks_rules_find_provider_secrets(text, rule):
    assert rule in {f.rule for f in find_secrets(text)}
    assert "api_key" in detect_secrets(text)


@pytest.mark.parametrize(
    "text",
    [
        "AKIAIOSFODNN7EXAMPLE",  # AWS's documented example key is allowlisted.
        "The password policy requires twelve characters.",
        "def add(a, b):\n    return a + b\n",
        "token = os.environ['GITHUB_TOKEN']",
    ],
)
def test_benign_text_is_not_a_secret(text):
    assert not detect_secrets(text)


def test_redaction_covers_ruleset_findings():
    payload = {"note": f"deploy with {SLACK} today", "list": [STRIPE]}
    redacted = json.dumps(redact(payload))
    assert SLACK not in redacted and STRIPE not in redacted
    assert "[REDACTED:api_key]" in redacted and "deploy with" in redacted


def test_scanning_is_linear_on_adversarial_input():
    for text in ("api_key=" + "a" * 200_000 + "!", "-----BEGIN " * 50_000, "x" * 2_000_000):
        started = time.perf_counter()
        find_secrets(text)
        assert time.perf_counter() - started < 5


@pytest.mark.parametrize(
    "text,category",
    [
        ("card 4111 1111 1111 1111 exp 12/29", "credit_card"),
        ("amex 378282246310005", "credit_card"),
        ("SSN 123-45-6789", "ssn"),
        ("IBAN GB82 WEST 1234 5698 7654 32", "iban"),
        ("mail ada@example.org", "email"),
        ("call +1 415 555 2671", "phone"),
        ("call (415) 555-2671", "phone"),
    ],
)
def test_pii_found(text, category):
    assert category in {c for c, _, _ in find_pii(text)}


@pytest.mark.parametrize(
    "text",
    [
        "card 4111 1111 1111 1112",  # Fails Luhn.
        "SSN 000-12-3456",
        "SSN 666-12-3456",
        "IBAN GB00 WEST 1234 5698 7654 32",  # Bad checksum.
        "released 2026-10-08 as version 1.2.3.4",
        "order 1234567890123",  # Not a card prefix / Luhn.
    ],
)
def test_pii_false_positives_rejected(text):
    assert not find_pii(text)


def test_pii_redaction_keeps_contacts_but_hides_identifiers():
    text = "Refund ada@example.org card 4111-1111-1111-1111 SSN 123-45-6789"
    redacted = redact({"note": text})["note"]
    assert "ada@example.org" in redacted
    assert "4111" not in redacted and "123-45-6789" not in redacted
    assert "[REDACTED:credit_card]" in redacted and "[REDACTED:ssn]" in redacted


@given(
    digits=st.lists(st.integers(0, 9), min_size=14, max_size=14),
    group=st.sampled_from([" ", "-", ""]),
)
def test_any_luhn_valid_visa_is_found_and_redacted(digits, group):
    body = [4, *digits]
    check = next(d for d in range(10) if luhn("".join(map(str, body + [d]))))
    number = "".join(map(str, body + [check]))
    formatted = group.join(number[i : i + 4] for i in range(0, 16, 4))
    assert "credit_card" in detect_pii(f"pay {formatted} now")
    assert number[-4:] not in redact(f"pay {formatted} now").replace("[REDACTED:credit_card]", "")


def test_policy_can_deny_outbound_card_numbers(make_guard):
    guard = make_guard(
        policy={
            "version": 1,
            "rules": [
                {"capability": "email.send", "sensitive_data": ["credit_card"], "effect": "deny"},
                {"capability": "email.send", "effect": "allow"},
            ],
            "risk": {"ask": 99, "strong": 99, "deny": 100},
        }
    )

    @guard.tool(capability="email.send")
    def send(to: str, body: str):
        return "sent"

    assert send("ada@example.org", "Your order shipped") == "sent"
    with pytest.raises(GuardDenied, match="Policy rule 1: deny"):
        send("ada@example.org", "Card on file: 4111 1111 1111 1111")
    logged = json.dumps(read_log(guard.audit.path))
    assert "4111 1111 1111 1111" not in logged


def test_outbound_identifiers_raise_risk(make_guard):
    guard = make_guard([{"capability": "network.request", "effect": "allow"}])

    @guard.tool(capability="network.request")
    def post(url: str, body: str):
        return "ok"

    assert post("https://api.example.com", "hello") == "ok"
    with pytest.raises(GuardDenied) as error:
        post("https://api.example.com", "ssn 123-45-6789")
    assert "Financial or government identifier in outbound payload" in error.value.decision.reasons
