"""Slack approvals: a message with buttons, and a verified handler for button clicks.

Setup: create a Slack app with a bot token (``chat:write``), invite it to a channel, turn
on Interactivity with the request URL ``<dashboard>/slack/actions``, and link approvers
to Slack users (``agentguard approvers add NAME --slack-user U123``). The dashboard
verifies Slack's signing secret on every click. Strong approval is never given in Slack.
"""

import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs

import httpx

from agentguard.approval.webhook import summarize

ACTIONS = {
    "agentguard_approve_once": ("once", None),
    "agentguard_allow_tool_10": ("tool", 10),
    "agentguard_reject": (None, None),
}


def _text(summary):
    reasons = "\n".join(f"• {reason}" for reason in summary["reasons"][:6]) or "• (none)"
    arguments = json.dumps(summary["arguments"], sort_keys=True)
    if len(arguments) > 600:
        arguments = arguments[:600] + "…"
    return (
        f"*AgentGuard approval needed* (`{summary['id']}`)\n"
        f"Agent `{summary['agent_id']}` wants `{summary['tool']}` "
        f"({summary['capability']}) in {summary['environment']}. Risk {summary['risk']}/100.\n"
        f"{reasons}\n```{arguments}```"
    )


def build_message(request, *, interactive=True, dashboard_url=None):
    summary = summarize(request, dashboard_url)
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": _text(summary)}}]
    buttons = []
    if interactive and not summary["strong_required"]:
        buttons = [
            {
                "type": "button",
                "action_id": "agentguard_approve_once",
                "text": {"type": "plain_text", "text": "Approve once"},
                "style": "primary",
                "value": summary["id"],
            },
            {
                "type": "button",
                "action_id": "agentguard_allow_tool_10",
                "text": {"type": "plain_text", "text": "Allow this tool 10 min"},
                "value": summary["id"],
            },
            {
                "type": "button",
                "action_id": "agentguard_reject",
                "text": {"type": "plain_text", "text": "Reject"},
                "style": "danger",
                "value": summary["id"],
            },
        ]
    if summary.get("review_url"):
        buttons.append(
            {
                "type": "button",
                "action_id": "agentguard_open",
                "text": {"type": "plain_text", "text": "Open dashboard"},
                "url": summary["review_url"],
            }
        )
    if summary["strong_required"]:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "Strong approval required: use the dashboard."}
                ],
            }
        )
    if buttons:
        blocks.append({"type": "actions", "elements": buttons})
    fallback = f"AgentGuard approval needed: {summary['tool']} ({summary['id']})"
    return {"text": fallback, "blocks": blocks}


class SlackNotifier:
    """Post approval requests to Slack.

    With ``bot_token`` and ``channel``: interactive buttons (needs the dashboard's
    ``/slack/actions`` endpoint). With ``webhook_url``: a message linking to the dashboard.
    """

    def __init__(
        self,
        *,
        bot_token=None,
        channel=None,
        webhook_url=None,
        dashboard_url=None,
        timeout=5.0,
        client=None,
    ):
        if not (bot_token and channel) and not webhook_url:
            raise ValueError("Provide bot_token and channel, or webhook_url")
        self.bot_token, self.channel, self.webhook_url = bot_token, channel, webhook_url
        self.dashboard_url = dashboard_url
        self.client = client or httpx.Client(timeout=timeout, trust_env=False)

    def notify(self, request):
        if self.bot_token:
            message = build_message(request, interactive=True, dashboard_url=self.dashboard_url)
            response = self.client.post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {self.bot_token}"},
                json={"channel": self.channel, **message},
            )
            response.raise_for_status()
            if not response.json().get("ok"):
                raise RuntimeError(f"Slack error: {response.json().get('error')}")
        else:
            message = build_message(request, interactive=False, dashboard_url=self.dashboard_url)
            self.client.post(self.webhook_url, json=message).raise_for_status()


def verify_slack_signature(signing_secret, timestamp, body, received, *, now=None):
    """Slack's v0 request signature, rejecting requests older than five minutes."""
    try:
        if abs((now or time.time()) - int(timestamp)) > 300:
            return False
    except (TypeError, ValueError):
        return False
    secret = signing_secret.encode() if isinstance(signing_secret, str) else signing_secret
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret, base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, received or "")


def handle_action(store, body: bytes):
    """Apply a verified Slack button click. Returns the text to show in Slack."""
    payload = json.loads(parse_qs(body.decode())["payload"][0])
    user = payload.get("user", {}).get("id")
    approver = store.approver_for_slack(user)
    if approver is None:
        return "You are not an AgentGuard approver."
    action = (payload.get("actions") or [{}])[0]
    if action.get("action_id") not in ACTIONS:
        return "Unknown action."
    scope, minutes = ACTIONS[action["action_id"]]
    try:
        request = store.resolve(
            action.get("value"),
            approved=scope is not None,
            approver=approver["name"],
            scope=scope or "once",
            minutes=minutes,
        )
    except (KeyError, ValueError, PermissionError) as exc:
        return f"Not applied: {exc}"
    if request["status"] == "rejected":
        return f"Rejected by {approver['name']}."
    detail = "for this one call" if scope == "once" else f"for {request['tool']} for {minutes} min"
    return f"Approved by {approver['name']} {detail}."


def post_response(response_url, text, client=None):
    """Replace the original Slack message with the outcome. Only Slack's own hook URLs."""
    if not str(response_url).startswith("https://hooks.slack.com/"):
        return
    client = client or httpx.Client(timeout=5.0, trust_env=False)
    client.post(response_url, json={"replace_original": True, "text": text})
