# Dashboard

```sh
pip install "agentguard-oss[dashboard]"
agentguard approvers add alice
agentguard dashboard --audit agentguard.jsonl --store agentguard-approvals.db
```

Open <http://127.0.0.1:8765> and sign in with the approver token.

| Tab | What it shows |
| --- | --- |
| **Approvals** | Pending requests with agent, environment, risk, reasons and redacted arguments. Approve once, for the same call, a tool or a capability for N minutes, or reject with a note. Active grants (revocable) and recent decisions. Refreshes every 5 seconds. |
| **Audit log** | Newest events first, with chain verification status, filters by decision and stage, full-text search, dry-run markers, and each action's timeline (proposed → authorized → executing → executed → observed). |
| **Policy report** | Calls that were asked about or denied, grouped by tool and reason, with counts, maximum risk and an example. Tick *Dry-run calls only* to tune a policy from a `mode="dry-run"` session. |

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--audit` | `agentguard.jsonl` | Audit log to show (rotated segments included) |
| `--store` | `agentguard-approvals.db` | Approval store shared with your agents' `QueueApproval` |
| `--host`, `--port` | `127.0.0.1`, `8765` | Listen address |
| `--audit-key-env VAR` | | Verify audit signatures with the key in `VAR` |
| `--slack-signing-secret-env VAR` | | Enable `/slack/actions` for Slack buttons |
| `--secure-cookies` | off | Mark the session cookie `Secure` (use behind HTTPS) |

## Security

- Every page and API call needs an approver. Browsers exchange a token for an `HttpOnly`,
  `SameSite=Strict` session cookie valid for 12 hours. Other systems send
  `Authorization: Bearer <token>`.
- Cookie-authenticated writes also require an `X-AgentGuard-CSRF: 1` header, which other
  origins cannot send.
- Strong approval requires re-entering the approver's own token for that decision.
- Pages use a strict Content-Security-Policy (no inline script) and render all audit and
  request data as text.
- It binds to localhost by default. To share it, put it behind an HTTPS reverse proxy with
  `--secure-cookies`, and restrict who can reach it.

## API

All endpoints return JSON and need an approver.

| Method and path | Purpose |
| --- | --- |
| `POST /api/login` `{"token"}` / `POST /api/logout` | Browser session |
| `GET /api/me` | Current approver |
| `GET /api/approvals?status=pending` | Requests, newest first |
| `GET /api/approvals/{id}` | One request |
| `POST /api/approvals/{id}/decision` | `{"approve": bool, "scope": "once"\|"action"\|"tool"\|"capability", "minutes": int, "note": str, "strong": bool, "token": str}` |
| `GET /api/grants` / `POST /api/grants/{id}/revoke` | Active grants |
| `GET /api/events?decision=&stage=&tool=&agent=&q=&offset=&limit=` | Verified audit events |
| `GET /api/events/{event_id}` | One event and its action's timeline |
| `GET /api/report?dry_run_only=1` | Policy report |
| `POST /slack/actions` | Slack interactivity (signature-verified, no login) |
