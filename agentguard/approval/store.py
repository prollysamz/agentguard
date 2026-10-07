"""Shared approval state in SQLite: requests, grants, approvers and dashboard logins.

One file can be shared by agent processes (which submit requests and use grants) and the
dashboard (where approvers decide). Every write is a short IMMEDIATE transaction.
"""

import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path

from agentguard.risk.secrets import redact

SCOPES = ("once", "action", "tool", "capability")
MAX_GRANT_MINUTES = 24 * 60
ONCE_GRANT_MINUTES = 15  # How long an approved one-time action waits for its retry.

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL,
    session_id TEXT, agent_id TEXT, environment TEXT, tool TEXT, capability TEXT,
    action_hash TEXT NOT NULL, action_json TEXT NOT NULL, risk INTEGER, reasons_json TEXT,
    strong_required INTEGER NOT NULL, decided_by TEXT, decided_at REAL, note TEXT,
    grant_id TEXT
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(status, created);
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL, scope TEXT NOT NULL,
    agent_id TEXT, environment TEXT, tool TEXT, capability TEXT, action_hash TEXT,
    approved_by TEXT NOT NULL, strong INTEGER NOT NULL, max_uses INTEGER,
    uses INTEGER NOT NULL DEFAULT 0, revoked_by TEXT, request_id TEXT
);
CREATE TABLE IF NOT EXISTS approvers (
    name TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, created REAL NOT NULL,
    slack_user_id TEXT UNIQUE, can_strong INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS logins (
    token_hash TEXT PRIMARY KEY, approver TEXT NOT NULL, created REAL NOT NULL,
    expires REAL NOT NULL
);
"""


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def action_fingerprint(action) -> str:
    """Identifies one exact call: tool, capability, full arguments, agent and environment."""
    body = {
        "tool": action.tool,
        "capability": action.capability,
        "arguments": action.arguments,
        "agent_id": action.agent_id,
        "environment": action.context.environment,
        "working_directory": action.context.working_directory,
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


class ApprovalStore:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _transaction(self):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def _rows(self, query, parameters=()):
        with closing(self._connect()) as connection:
            return [dict(row) for row in connection.execute(query, parameters)]

    # ------------------------------------------------------------------ requests

    def submit(self, action, decision, *, ttl=3600.0):
        """Queue a request. -> (request, created)

        An identical call that is already pending, or was rejected within ``ttl``, returns
        that request instead, so a retrying agent does not flood approvers.
        """
        now, fingerprint = time.time(), action_fingerprint(action)
        with self._transaction() as connection:
            connection.execute(
                "UPDATE requests SET status='expired' WHERE status='pending' AND expires<=?",
                (now,),
            )
            existing = connection.execute(
                "SELECT * FROM requests WHERE action_hash=? AND session_id=? AND "
                "(status='pending' OR (status='rejected' AND decided_at>?)) "
                "ORDER BY created DESC LIMIT 1",
                (fingerprint, action.session_id, now - ttl),
            ).fetchone()
            if existing:
                return _request(existing), False
            request_id = "apr_" + secrets.token_hex(12)
            connection.execute(
                "INSERT INTO requests (id, created, expires, status, session_id, agent_id, "
                "environment, tool, capability, action_hash, action_json, risk, reasons_json, "
                "strong_required) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    now,
                    now + ttl,
                    "pending",
                    action.session_id,
                    action.agent_id,
                    action.context.environment,
                    action.tool,
                    action.capability,
                    fingerprint,
                    json.dumps(redact(action.model_dump()), sort_keys=True, ensure_ascii=True),
                    decision.risk_score,
                    json.dumps(redact(list(decision.reasons))),
                    int(decision.strong_approval),
                ),
            )
            row = connection.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            return _request(row), True

    def get(self, request_id):
        rows = self._rows("SELECT * FROM requests WHERE id=?", (request_id,))
        if not rows:
            return None
        request = _request(rows[0])
        if request["status"] == "pending" and request["expires"] <= time.time():
            request["status"] = "expired"
        return request

    def list_requests(self, status=None, limit=100):
        now = time.time()
        with self._transaction() as connection:
            connection.execute(
                "UPDATE requests SET status='expired' WHERE status='pending' AND expires<=?",
                (now,),
            )
        if status:
            rows = self._rows(
                "SELECT * FROM requests WHERE status=? ORDER BY created DESC LIMIT ?",
                (status, limit),
            )
        else:
            rows = self._rows("SELECT * FROM requests ORDER BY created DESC LIMIT ?", (limit,))
        return [_request(row) for row in rows]

    def resolve(
        self, request_id, *, approved, approver, scope="once", minutes=None, strong=False, note=""
    ):
        """Approve or reject a pending request. Approval creates a grant for ``scope``."""
        if scope not in SCOPES:
            raise ValueError(f"scope must be one of {SCOPES}")
        if approved and scope != "once":
            if not isinstance(minutes, int) or not 1 <= minutes <= MAX_GRANT_MINUTES:
                raise ValueError(f"minutes must be an integer from 1 to {MAX_GRANT_MINUTES}")
        now = time.time()
        with self._transaction() as connection:
            person = connection.execute(
                "SELECT * FROM approvers WHERE name=?", (approver,)
            ).fetchone()
            if person is None:
                raise PermissionError("Unknown approver")
            if strong and not person["can_strong"]:
                raise PermissionError("This approver cannot give strong approval")
            row = connection.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if row is None:
                raise KeyError(request_id)
            if row["status"] != "pending" or row["expires"] <= now:
                raise ValueError("Request is no longer pending")
            if approved and row["strong_required"] and not strong:
                raise PermissionError("This request requires strong approval")
            grant_id = None
            if approved:
                grant_id = "grt_" + secrets.token_hex(12)
                duration = ONCE_GRANT_MINUTES if scope == "once" else minutes
                connection.execute(
                    "INSERT INTO grants (id, created, expires, scope, agent_id, environment, "
                    "tool, capability, action_hash, approved_by, strong, max_uses, request_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        grant_id,
                        now,
                        now + duration * 60,
                        "action" if scope == "once" else scope,
                        row["agent_id"],
                        row["environment"],
                        row["tool"],
                        row["capability"],
                        row["action_hash"],
                        approver,
                        int(strong),
                        1 if scope == "once" else None,
                        request_id,
                    ),
                )
            connection.execute(
                "UPDATE requests SET status=?, decided_by=?, decided_at=?, note=?, grant_id=? "
                "WHERE id=?",
                (
                    "approved" if approved else "rejected",
                    approver,
                    now,
                    note[:500],
                    grant_id,
                    request_id,
                ),
            )
            return _request(
                connection.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            )

    # ------------------------------------------------------------------ grants

    def use_grant(self, action, decision):
        """Consume a matching active grant, most specific first. Returns it or None."""
        now = time.time()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM grants WHERE revoked_by IS NULL AND expires>? "
                "AND (max_uses IS NULL OR uses<max_uses) AND agent_id=? AND environment=? "
                "AND (strong=1 OR ?=0) AND ("
                "(scope='action' AND action_hash=?) OR (scope='tool' AND tool=?) "
                "OR (scope='capability' AND capability=?)) "
                "ORDER BY CASE scope WHEN 'action' THEN 0 WHEN 'tool' THEN 1 ELSE 2 END, "
                "created DESC LIMIT 1",
                (
                    now,
                    action.agent_id,
                    action.context.environment,
                    int(decision.strong_approval),
                    action_fingerprint(action),
                    action.tool,
                    action.capability,
                ),
            ).fetchone()
            if row is None:
                return None
            connection.execute("UPDATE grants SET uses=uses+1 WHERE id=?", (row["id"],))
            return dict(row)

    def list_grants(self, active_only=True):
        if active_only:
            return self._rows(
                "SELECT * FROM grants WHERE revoked_by IS NULL AND expires>? "
                "AND (max_uses IS NULL OR uses<max_uses) ORDER BY created DESC",
                (time.time(),),
            )
        return self._rows("SELECT * FROM grants ORDER BY created DESC")

    def revoke_grant(self, grant_id, by):
        with self._transaction() as connection:
            updated = connection.execute(
                "UPDATE grants SET revoked_by=? WHERE id=? AND revoked_by IS NULL",
                (by, grant_id),
            ).rowcount
        if not updated:
            raise KeyError(grant_id)

    # ------------------------------------------------------------------ approvers

    def add_approver(self, name, *, slack_user_id=None, can_strong=False):
        """Create an approver and return their token. Only its hash is stored."""
        if not name or len(name) > 100:
            raise ValueError("Approver name must be 1-100 characters")
        token = "agt_" + secrets.token_urlsafe(32)
        with self._transaction() as connection:
            taken = connection.execute(
                "SELECT 1 FROM approvers WHERE name=? OR (slack_user_id IS NOT NULL "
                "AND slack_user_id=?)",
                (name, slack_user_id),
            ).fetchone()
            if taken:
                raise ValueError(f"Approver {name} or that Slack user already exists")
            connection.execute(
                "INSERT INTO approvers (name, token_hash, created, slack_user_id, can_strong) "
                "VALUES (?,?,?,?,?)",
                (name, _digest(token), time.time(), slack_user_id, int(can_strong)),
            )
        return token

    def remove_approver(self, name):
        with self._transaction() as connection:
            connection.execute("DELETE FROM logins WHERE approver=?", (name,))
            if not connection.execute("DELETE FROM approvers WHERE name=?", (name,)).rowcount:
                raise ValueError(f"No approver named {name}")

    def list_approvers(self):
        return self._rows(
            "SELECT name, created, slack_user_id, can_strong FROM approvers ORDER BY name"
        )

    def authenticate(self, token):
        """The approver for a token, or None."""
        if not isinstance(token, str) or not token.startswith("agt_"):
            return None
        rows = self._rows(
            "SELECT name, slack_user_id, can_strong FROM approvers WHERE token_hash=?",
            (_digest(token),),
        )
        return rows[0] if rows else None

    def approver_for_slack(self, slack_user_id):
        rows = self._rows(
            "SELECT name, slack_user_id, can_strong FROM approvers WHERE slack_user_id=?",
            (slack_user_id,),
        )
        return rows[0] if rows else None

    # ------------------------------------------------------------------ dashboard logins

    def create_login(self, approver, hours=12):
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._transaction() as connection:
            connection.execute("DELETE FROM logins WHERE expires<=?", (now,))
            connection.execute(
                "INSERT INTO logins (token_hash, approver, created, expires) VALUES (?,?,?,?)",
                (_digest(token), approver, now, now + hours * 3600),
            )
        return token

    def login_approver(self, token):
        if not isinstance(token, str) or not token:
            return None
        rows = self._rows(
            "SELECT a.name, a.slack_user_id, a.can_strong FROM logins l "
            "JOIN approvers a ON a.name=l.approver WHERE l.token_hash=? AND l.expires>?",
            (_digest(token), time.time()),
        )
        return rows[0] if rows else None

    def delete_login(self, token):
        with self._transaction() as connection:
            connection.execute("DELETE FROM logins WHERE token_hash=?", (_digest(token or ""),))


def _request(row):
    request = dict(row)
    request["action"] = json.loads(request.pop("action_json"))
    request["reasons"] = json.loads(request.pop("reasons_json") or "[]")
    request["strong_required"] = bool(request["strong_required"])
    request.pop("action_hash", None)
    return request
