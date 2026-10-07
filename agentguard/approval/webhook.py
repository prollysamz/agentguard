"""Signed webhook notifications for approval requests.

The receiver verifies the signature with ``verify_signature`` and decides by calling the
dashboard API: ``POST /api/approvals/<id>/decision`` with ``Authorization: Bearer
<approver token>``.
"""

import hashlib
import hmac
import json
import time

import httpx


def summarize(request, dashboard_url=None):
    """The fields channels show approvers. Action data is already redacted."""
    summary = {
        "id": request["id"],
        "tool": request["tool"],
        "capability": request["capability"],
        "agent_id": request["agent_id"],
        "environment": request["environment"],
        "risk": request["risk"],
        "reasons": request["reasons"],
        "strong_required": request["strong_required"],
        "arguments": request["action"].get("arguments", {}),
        "created": request["created"],
        "expires": request["expires"],
    }
    if dashboard_url:
        base = dashboard_url.rstrip("/")
        summary["review_url"] = f"{base}/#approvals/{request['id']}"
        summary["decision_url"] = f"{base}/api/approvals/{request['id']}/decision"
    return summary


def signature(secret: bytes, timestamp: str, body: bytes) -> str:
    return (
        "sha256=" + hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    )


def verify_signature(secret, timestamp, body, received, *, tolerance=300, now=None):
    """True if ``received`` is a valid signature of ``body`` sent within ``tolerance`` seconds."""
    secret = secret.encode() if isinstance(secret, str) else secret
    try:
        age = abs((now or time.time()) - int(timestamp))
    except (TypeError, ValueError):
        return False
    return age <= tolerance and hmac.compare_digest(signature(secret, timestamp, body), received)


class WebhookNotifier:
    """POST ``{"type": "approval.requested", "request": {...}}`` signed with ``secret``.

    Headers: ``X-AgentGuard-Timestamp`` and ``X-AgentGuard-Signature: sha256=<hex>`` over
    ``"<timestamp>.<body>"``.
    """

    def __init__(self, url, *, secret, dashboard_url=None, timeout=5.0, client=None):
        if not secret:
            raise ValueError("A webhook secret is required")
        self.url = url
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.dashboard_url = dashboard_url
        self.client = client or httpx.Client(timeout=timeout, trust_env=False)

    def notify(self, request):
        body = json.dumps(
            {"type": "approval.requested", "request": summarize(request, self.dashboard_url)},
            sort_keys=True,
        ).encode()
        timestamp = str(int(time.time()))
        self.client.post(
            self.url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-AgentGuard-Timestamp": timestamp,
                "X-AgentGuard-Signature": signature(self.secret, timestamp, body),
            },
        ).raise_for_status()
