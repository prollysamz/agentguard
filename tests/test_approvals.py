import json
import sqlite3
import threading
import time
from urllib.parse import urlencode

import httpx
import pytest

from agentguard import ApprovalPending, Guard, GuardDenied
from agentguard.adapters._common import denial_result
from agentguard.approval import ApprovalStore, QueueApproval, SlackNotifier, WebhookNotifier
from agentguard.approval import slack as slack_module
from agentguard.approval.webhook import verify_signature
from agentguard.audit.reader import read_log

POLICY = {
    "version": 1,
    "rules": [
        {"capability": "shell.execute", "effect": "ask"},
        {"capability": "filesystem.read", "effect": "ask"},
    ],
}


@pytest.fixture
def store(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    store.add_approver("alice")
    store.add_approver("root", can_strong=True)
    return store


def make(tmp_path, store, *, wait=0.0, policy=POLICY, agent_id="agent", environment="test"):
    guard = Guard(
        policy,
        audit=tmp_path / f"audit-{agent_id}.jsonl",
        agent_id=agent_id,
        context={"working_directory": str(tmp_path), "environment": environment},
        approval=QueueApproval(store, wait=wait, poll_interval=0.02),
    )
    ran = []

    @guard.tool(capability="shell.execute")
    def run(cmd: str):
        ran.append(cmd)
        return f"ran {cmd}"

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        ran.append(path)
        return "read"

    return guard, ran


def pending_id(guard, name, arguments):
    with pytest.raises(ApprovalPending) as error:
        guard.call(name, arguments)
    return error.value.request_id


def test_ask_returns_pending_immediately_then_retry_runs(tmp_path, store):
    guard, ran = make(tmp_path, store)
    started = time.monotonic()
    request_id = pending_id(guard, "run", {"cmd": "make deploy"})
    assert time.monotonic() - started < 1  # The agent is not blocked.
    assert ran == [] and store.get(request_id)["status"] == "pending"
    # Retrying before a decision reuses the same request.
    assert pending_id(guard, "run", {"cmd": "make deploy"}) == request_id
    store.resolve(request_id, approved=True, approver="alice")
    assert guard.call("run", {"cmd": "make deploy"}) == "ran make deploy"
    # "Once" was used up: the next identical call asks again.
    assert pending_id(guard, "run", {"cmd": "make deploy"}) != request_id
    events = read_log(guard.audit.path)
    pending = [e for e in events if e.get("approval_status") == "pending"]
    assert pending[0]["approval_request_id"] == request_id
    authorized = [e for e in events if e["stage"] == "authorized"]
    assert authorized[0]["approved_by"].startswith("alice (grant grt_")


def test_rejection_is_remembered(tmp_path, store):
    guard, ran = make(tmp_path, store)
    request_id = pending_id(guard, "run", {"cmd": "rm build"})
    store.resolve(request_id, approved=False, approver="alice", note="not today")
    with pytest.raises(GuardDenied) as error:
        guard.call("run", {"cmd": "rm build"})
    assert not isinstance(error.value, ApprovalPending) and ran == []
    assert len(store.list_requests()) == 1  # No new request was created.


def test_time_boxed_tool_grant(tmp_path, store, monkeypatch):
    guard, ran = make(tmp_path, store)
    request_id = pending_id(guard, "run", {"cmd": "pytest"})
    store.resolve(request_id, approved=True, approver="alice", scope="tool", minutes=10)
    for command in ("pytest", "pytest -k slow", "ruff check ."):
        guard.call("run", {"cmd": command})
    assert ran == ["pytest", "pytest -k slow", "ruff check ."]
    pending_id(guard, "read", {"path": "notes.txt"})  # Another tool still asks.
    # Another agent does not inherit the grant.
    other, _ = make(tmp_path, store, agent_id="other")
    pending_id(other, "run", {"cmd": "pytest"})
    # After ten minutes the grant is gone.
    later = time.time() + 11 * 60
    monkeypatch.setattr(time, "time", lambda: later)
    pending_id(guard, "run", {"cmd": "pytest"})


def test_grant_revocation(tmp_path, store):
    guard, _ = make(tmp_path, store)
    request_id = pending_id(guard, "run", {"cmd": "pytest"})
    request = store.resolve(request_id, approved=True, approver="alice", scope="action", minutes=5)
    guard.call("run", {"cmd": "pytest"})
    guard.call("run", {"cmd": "pytest"})  # "action" scope allows repeats until expiry.
    store.revoke_grant(request["grant_id"], by="alice")
    pending_id(guard, "run", {"cmd": "pytest"})


def test_wait_mode_resolves_within_the_call(tmp_path, store):
    guard, ran = make(tmp_path, store, wait=5)

    def approve_soon():
        for _ in range(100):
            pending = store.list_requests(status="pending")
            if pending:
                store.resolve(pending[0]["id"], approved=True, approver="alice")
                return
            time.sleep(0.02)

    threading.Thread(target=approve_soon).start()
    assert guard.call("run", {"cmd": "deploy"}) == "ran deploy"


def test_strong_approval_rules(tmp_path, store):
    strong_policy = {**POLICY, "risk": {"ask": 30, "strong": 30, "deny": 100}}
    guard, ran = make(tmp_path, store, policy=strong_policy)
    request_id = pending_id(guard, "run", {"cmd": "deploy"})
    assert store.get(request_id)["strong_required"]
    with pytest.raises(PermissionError, match="strong approval"):
        store.resolve(request_id, approved=True, approver="alice")
    with pytest.raises(PermissionError, match="cannot give strong"):
        store.resolve(request_id, approved=True, approver="alice", strong=True)
    store.resolve(request_id, approved=True, approver="root", strong=True)
    assert guard.call("run", {"cmd": "deploy"}) == "ran deploy"


def test_resolve_validation(tmp_path, store):
    guard, _ = make(tmp_path, store)
    request_id = pending_id(guard, "run", {"cmd": "x"})
    with pytest.raises(PermissionError, match="Unknown approver"):
        store.resolve(request_id, approved=True, approver="mallory")
    with pytest.raises(ValueError, match="minutes"):
        store.resolve(request_id, approved=True, approver="alice", scope="tool", minutes=0)
    store.resolve(request_id, approved=False, approver="alice")
    with pytest.raises(ValueError, match="no longer pending"):
        store.resolve(request_id, approved=True, approver="alice")


def test_tokens_are_hashed_and_authenticate(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    token = store.add_approver("bob", slack_user_id="U1")
    assert store.authenticate(token)["name"] == "bob"
    assert store.authenticate(token + "x") is None and store.authenticate("") is None
    with sqlite3.connect(store.path) as connection:
        stored = connection.execute("SELECT token_hash FROM approvers").fetchone()[0]
    assert token not in stored
    login = store.create_login("bob")
    assert store.login_approver(login)["name"] == "bob"
    store.remove_approver("bob")
    assert store.authenticate(token) is None and store.login_approver(login) is None


def test_pending_result_for_agents(tmp_path, store):
    guard, _ = make(tmp_path, store)
    with pytest.raises(ApprovalPending) as error:
        guard.call("run", {"cmd": "deploy"})
    result = denial_result(error.value)
    assert result["error"] == "Approval pending"
    assert result["request_id"] == error.value.request_id


def test_webhook_notifier_signs_requests(tmp_path, store):
    received = []
    notifier = WebhookNotifier(
        "https://hooks.example.test/agentguard",
        secret="whsec",
        dashboard_url="https://guard.example.test",
        client=httpx.Client(
            transport=httpx.MockTransport(lambda r: received.append(r) or httpx.Response(200))
        ),
    )
    guard = Guard(
        POLICY,
        audit=tmp_path / "audit.jsonl",
        context={"working_directory": str(tmp_path)},
        approval=QueueApproval(store, notifiers=[notifier]),
    )
    guard.tool(capability="shell.execute", name="run")(_run)
    request_id = pending_id(guard, "run", {"cmd": "deploy", "password": "hunter2"})
    for _ in range(100):
        if received:
            break
        time.sleep(0.02)
    request = received[0]
    body = json.loads(request.content)
    assert body["request"]["id"] == request_id
    assert body["request"]["decision_url"].endswith(f"/api/approvals/{request_id}/decision")
    assert "hunter2" not in request.content.decode()  # Arguments are redacted.
    timestamp, signature = (
        request.headers["X-AgentGuard-Timestamp"],
        request.headers["X-AgentGuard-Signature"],
    )
    assert verify_signature("whsec", timestamp, request.content, signature)
    assert not verify_signature("whsec", timestamp, request.content + b" ", signature)
    assert not verify_signature("whsec", str(int(timestamp) - 3600), request.content, signature)


def _run(cmd: str, password: str = "") -> str:
    return "ran"


def test_slack_message_and_signed_button_click(tmp_path, store):
    store.add_approver("carol", slack_user_id="U42")
    guard, ran = make(tmp_path, store)
    request_id = pending_id(guard, "run", {"cmd": "deploy"})
    message = slack_module.build_message(store.get(request_id))
    buttons = [e["action_id"] for e in message["blocks"][-1]["elements"]]
    assert buttons == ["agentguard_approve_once", "agentguard_allow_tool_10", "agentguard_reject"]

    payload = {
        "user": {"id": "U42"},
        "actions": [{"action_id": "agentguard_allow_tool_10", "value": request_id}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode()
    timestamp = str(int(time.time()))
    import hashlib
    import hmac

    signature = (
        "v0="
        + hmac.new(
            b"slack-secret", b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256
        ).hexdigest()
    )
    assert slack_module.verify_slack_signature("slack-secret", timestamp, body, signature)
    assert not slack_module.verify_slack_signature("other", timestamp, body, signature)
    assert "Approved by carol" in slack_module.handle_action(store, body)
    assert guard.call("run", {"cmd": "anything"}) == "ran anything"

    stranger = urlencode({"payload": json.dumps({**payload, "user": {"id": "U999"}})}).encode()
    assert "not an AgentGuard approver" in slack_module.handle_action(store, stranger)


def test_slack_strong_requests_have_no_approve_buttons(tmp_path, store):
    guard, _ = make(
        tmp_path, store, policy={**POLICY, "risk": {"ask": 30, "strong": 30, "deny": 100}}
    )
    request_id = pending_id(guard, "run", {"cmd": "deploy"})
    message = slack_module.build_message(store.get(request_id), dashboard_url="https://g.test")
    elements = [e for b in message["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert [e["action_id"] for e in elements] == ["agentguard_open"]


def test_slack_notifier_posts_with_bot_token(tmp_path, store):
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={"ok": True})

    notifier = SlackNotifier(
        bot_token="xoxb-test",
        channel="C1",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    guard, _ = make(tmp_path, store)
    notifier.notify(store.get(pending_id(guard, "run", {"cmd": "deploy"})))
    assert sent[0].headers["Authorization"] == "Bearer xoxb-test"
    assert json.loads(sent[0].content)["channel"] == "C1"


def test_cli_manages_approvers_and_lists_requests(tmp_path, capsys):
    from agentguard.cli.main import main

    db = str(tmp_path / "cli.db")
    assert main(["approvers", "add", "dana", "--strong", "--slack-user", "U7", "--store", db]) == 0
    token = capsys.readouterr().out.strip().splitlines()[-1]
    store = ApprovalStore(db)
    assert store.authenticate(token)["can_strong"] == 1
    assert main(["approvers", "add", "dana", "--store", db]) == 1
    assert "already exists" in capsys.readouterr().err
    guard, _ = make(tmp_path, store)
    request_id = pending_id(guard, "run", {"cmd": "deploy"})
    assert main(["approvals", "list", "--status", "pending", "--store", db]) == 0
    assert request_id in capsys.readouterr().out
    assert main(["approvers", "remove", "dana", "--store", db]) == 0
    assert store.authenticate(token) is None
