import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

from agentguard import ApprovalPending, Guard, GuardDenied  # noqa: E402
from agentguard.approval import ApprovalStore, QueueApproval  # noqa: E402
from agentguard.audit.report import build_report, format_report  # noqa: E402
from agentguard.cli.main import main  # noqa: E402
from agentguard.dashboard.app import create_app  # noqa: E402

POLICY = {
    "version": 1,
    "rules": [
        {"capability": "shell.execute", "effect": "ask"},
        {"capability": "filesystem.read", "paths": ["./docs/**"], "effect": "allow"},
    ],
}


@pytest.fixture
def setup(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    tokens = {
        "alice": store.add_approver("alice"),
        "root": store.add_approver("root", can_strong=True),
        "slacker": store.add_approver("slacker", slack_user_id="U9"),
    }
    guard = Guard(
        POLICY,
        audit=tmp_path / "audit.jsonl",
        agent_id="builder",
        context={"working_directory": str(tmp_path)},
        approval=QueueApproval(store),
    )

    @guard.tool(capability="shell.execute")
    def run(cmd: str):
        return f"ran {cmd}"

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        return "text"

    app = create_app(audit_path=guard.audit.path, store=store, slack_signing_secret="slack-secret")
    return guard, store, tokens, TestClient(app)


def login(client, token):
    response = client.post("/api/login", json={"token": token})
    assert response.status_code == 200
    return response


def pending(guard, cmd="deploy"):
    with pytest.raises(ApprovalPending) as error:
        guard.call("run", {"cmd": cmd})
    return error.value.request_id


def test_pages_have_security_headers(setup):
    _, _, _, client = setup
    for path, kind in (("/", "text/html"), ("/app.js", "javascript"), ("/app.css", "text/css")):
        response = client.get(path)
        assert response.status_code == 200 and kind in response.headers["content-type"]
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert response.headers["x-frame-options"] == "DENY"


def test_everything_requires_an_approver(setup):
    _, _, tokens, client = setup
    for path in ("/api/me", "/api/approvals", "/api/events", "/api/report", "/api/grants"):
        assert client.get(path).status_code == 401
    assert client.post("/api/login", json={"token": "agt_wrong"}).status_code == 401
    response = login(client, tokens["alice"])
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/me").json() == {"name": "alice", "can_strong": False}
    client.post("/api/logout", headers={"X-AgentGuard-CSRF": "1"})
    assert client.get("/api/me").status_code == 401


def test_browser_decision_needs_csrf_header(setup):
    guard, store, tokens, client = setup
    request_id = pending(guard)
    login(client, tokens["alice"])
    url = f"/api/approvals/{request_id}/decision"
    assert client.post(url, json={"approve": True}).status_code == 401  # No CSRF header.
    response = client.post(
        url,
        json={"approve": True, "scope": "tool", "minutes": 10},
        headers={"X-AgentGuard-CSRF": "1"},
    )
    assert response.status_code == 200 and response.json()["decided_by"] == "alice"
    assert guard.call("run", {"cmd": "deploy"}) == "ran deploy"
    assert guard.call("run", {"cmd": "test"}) == "ran test"  # Tool grant covers it.
    grant = client.get("/api/grants").json()["grants"][0]
    assert grant["scope"] == "tool" and grant["approved_by"] == "alice"
    revoke = client.post(f"/api/grants/{grant['id']}/revoke", headers={"X-AgentGuard-CSRF": "1"})
    assert revoke.status_code == 200
    pending(guard, "after revoke")


def test_bearer_token_decisions_for_webhooks(setup):
    guard, _, tokens, client = setup
    request_id = pending(guard)
    url = f"/api/approvals/{request_id}/decision"
    bad = client.post(url, json={"approve": True}, headers={"Authorization": "Bearer agt_nope"})
    assert bad.status_code == 401
    response = client.post(
        url,
        json={"approve": False, "note": "change freeze"},
        headers={"Authorization": f"Bearer {tokens['alice']}"},
    )
    assert response.json()["status"] == "rejected"
    with pytest.raises(GuardDenied):
        guard.call("run", {"cmd": "deploy"})
    again = client.post(
        url, json={"approve": True}, headers={"Authorization": f"Bearer {tokens['alice']}"}
    )
    assert again.status_code == 409


def test_strong_approval_requires_reentering_token(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    root = store.add_approver("root", can_strong=True)
    alice = store.add_approver("alice")
    guard = Guard(
        {**POLICY, "risk": {"ask": 30, "strong": 30, "deny": 100}},
        audit=tmp_path / "audit.jsonl",
        context={"working_directory": str(tmp_path)},
        approval=QueueApproval(store),
    )
    guard.tool(capability="shell.execute", name="run")(_run)
    request_id = pending(guard)
    client = TestClient(create_app(audit_path=guard.audit.path, store=store))
    url = f"/api/approvals/{request_id}/decision"
    headers = {"Authorization": f"Bearer {root}"}
    assert client.post(url, json={"approve": True}, headers=headers).status_code == 403
    wrong = {"approve": True, "strong": True, "token": alice}
    assert client.post(url, json=wrong, headers=headers).status_code == 403
    right = {"approve": True, "strong": True, "token": root}
    assert client.post(url, json=right, headers=headers).status_code == 200
    assert guard.call("run", {"cmd": "deploy"}) == "ran"


def _run(cmd: str) -> str:
    return "ran"


def test_audit_log_api_filters_and_timeline(setup):
    guard, _, tokens, client = setup
    guard.call("read", {"path": "docs/a.md"})
    with pytest.raises(GuardDenied):
        guard.call("read", {"path": "secrets/key.txt"})
    login(client, tokens["alice"])
    data = client.get("/api/events").json()
    assert data["verified"] and data["total"] == data["verified_events"] > 0
    denied = client.get("/api/events", params={"decision": "deny", "stage": "denied"}).json()
    assert [e["tool"] for e in denied["events"]] == ["read"]
    searched = client.get("/api/events", params={"q": "docs/a.md", "stage": "observed"}).json()
    assert searched["total"] == 1
    detail = client.get(f"/api/events/{searched['events'][0]['event_id']}").json()
    assert [e["stage"] for e in detail["timeline"]] == [
        "proposed",
        "authorized",
        "executing",
        "executed",
        "observed",
    ]


def test_tampered_log_is_reported_not_shown(setup):
    guard, _, tokens, client = setup
    guard.call("read", {"path": "docs/a.md"})
    path = guard.audit.path
    lines = path.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk_score"] = 0
    path.write_text("\n".join([json.dumps(event), *lines[1:]]) + "\n")
    login(client, tokens["alice"])
    data = client.get("/api/events").json()
    assert data["verified"] is False and "chain" in data["error"] and data["events"] == []


def test_report_counts_dry_run_decisions(tmp_path, capsys):
    guard = Guard(
        POLICY,
        audit=tmp_path / "audit.jsonl",
        mode="dry-run",
        context={"working_directory": str(tmp_path)},
    )
    ran = []

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        ran.append(path)
        return "text"

    @guard.tool(capability="shell.execute")
    def run(cmd: str):
        ran.append(cmd)
        return "ok"

    for path in ("docs/a.md", "docs/b.md", "src/app.py", "~/.ssh/id_rsa"):
        guard.call("read", {"path": path})
    guard.call("run", {"cmd": "make"})
    from agentguard.audit.reader import read_log

    report = build_report(read_log(guard.audit.path), dry_run_only=True)
    assert report["decisions"] == {"allow": 2, "ask": 1, "deny": 2}
    deny = next(g for g in report["would_change"] if g["decision"] == "deny")
    assert deny["tool"] == "read" and deny["count"] == 2 and deny["executed_in_dry_run"] == 2
    assert {r["reason"] for r in deny["reasons"]} >= {"Sensitive credential file access"}
    assert len(ran) == 5  # Dry-run really executed everything.
    assert "read (filesystem.read): 2 call(s) denied" in format_report(report)
    assert main(["report", "--audit", str(guard.audit.path), "--dry-run-only"]) == 0
    assert "sent for approval" in capsys.readouterr().out


def test_slack_endpoint_verifies_signatures(setup):
    guard, store, _, client = setup
    request_id = pending(guard)
    payload = {
        "user": {"id": "U9"},
        "actions": [{"action_id": "agentguard_approve_once", "value": request_id}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode()
    timestamp = str(int(time.time()))
    signature = (
        "v0="
        + hmac.new(
            b"slack-secret", b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256
        ).hexdigest()
    )
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    forged = {**headers, "X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": "v0=00"}
    assert client.post("/slack/actions", content=body, headers=forged).status_code == 401
    assert store.get(request_id)["status"] == "pending"
    signed = {**headers, "X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": signature}
    assert client.post("/slack/actions", content=body, headers=signed).status_code == 200
    assert store.get(request_id)["decided_by"] == "slacker"
    assert guard.call("run", {"cmd": "deploy"}) == "ran deploy"
