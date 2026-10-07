"""AgentGuard dashboard: approval queue, audit log viewer and policy report.

Run with ``agentguard dashboard``. Every page and API call needs an approver: a browser
logs in with an approver token (exchanged for an HttpOnly, SameSite=Strict session cookie),
and other systems send ``Authorization: Bearer <approver token>``. Cookie-authenticated
writes also need the ``X-AgentGuard-CSRF`` header, which other origins cannot send.
"""

import json
import threading
from importlib.resources import files
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from agentguard.approval import slack
from agentguard.approval.store import SCOPES, ApprovalStore
from agentguard.audit.reader import read_log
from agentguard.audit.report import build_report
from agentguard.audit.segments import head_path, rotated_segments

COOKIE = "agentguard_session"
CSRF_HEADER = "x-agentguard-csrf"
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}


class EventCache:
    """Verified audit events, re-read only when the log or its checkpoint changes."""

    def __init__(self, path, key=None):
        self.path, self.key = Path(path), key
        self._stamp, self._events, self._error = None, [], None
        self._lock = threading.Lock()

    def _current_stamp(self):
        files = [*rotated_segments(self.path), self.path, head_path(self.path)]
        return tuple((f.name, f.stat().st_size, f.stat().st_mtime_ns) for f in files if f.exists())

    def load(self):
        with self._lock:
            stamp = self._current_stamp()
            if stamp != self._stamp:
                try:
                    self._events, self._error = read_log(self.path, self.key), None
                except FileNotFoundError:
                    self._events, self._error = [], None
                except (ValueError, OSError) as exc:
                    self._events, self._error = [], f"{type(exc).__name__}: {exc}"
                self._stamp = stamp
            return self._events, self._error


class _SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response


def create_app(
    *, audit_path, store, audit_key=None, slack_signing_secret=None, secure_cookies=False
):
    store = store if isinstance(store, ApprovalStore) else ApprovalStore(store)
    cache = EventCache(audit_path, audit_key)

    def approver(request: Request, *, write=False):
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            return store.authenticate(header[7:].strip())
        person = store.login_approver(request.cookies.get(COOKIE))
        if person and write and request.headers.get(CSRF_HEADER) != "1":
            return None
        return person

    def unauthorized():
        return JSONResponse({"error": "Not signed in"}, status_code=401)

    async def body(request):
        try:
            data = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    async def static(request):
        name, media = STATIC[request.url.path]
        return Response(
            files("agentguard.dashboard").joinpath("static", name).read_text(encoding="utf-8"),
            media_type=media,
        )

    async def login(request):
        data = await body(request)
        person = store.authenticate((data or {}).get("token"))
        if person is None:
            return JSONResponse({"error": "Invalid token"}, status_code=401)
        response = JSONResponse({"name": person["name"], "can_strong": bool(person["can_strong"])})
        response.set_cookie(
            COOKIE,
            store.create_login(person["name"]),
            max_age=12 * 3600,
            httponly=True,
            samesite="strict",
            secure=secure_cookies,
            path="/",
        )
        return response

    async def logout(request):
        if approver(request, write=True) is None:
            return unauthorized()
        store.delete_login(request.cookies.get(COOKIE))
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, path="/")
        return response

    async def me(request):
        person = approver(request)
        if person is None:
            return unauthorized()
        return JSONResponse({"name": person["name"], "can_strong": bool(person["can_strong"])})

    async def approvals(request):
        if approver(request) is None:
            return unauthorized()
        status = request.query_params.get("status") or None
        if status not in {None, "pending", "approved", "rejected", "expired"}:
            return JSONResponse({"error": "Unknown status"}, status_code=400)
        limit = _int(request.query_params.get("limit"), 100, 1, 500)
        return JSONResponse({"requests": store.list_requests(status=status, limit=limit)})

    async def approval(request):
        if approver(request) is None:
            return unauthorized()
        found = store.get(request.path_params["request_id"])
        if found is None:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return JSONResponse(found)

    async def decide(request):
        person = approver(request, write=True)
        if person is None:
            return unauthorized()
        data = await body(request)
        if data is None or type(data.get("approve")) is not bool:
            return JSONResponse({"error": "Send JSON with approve: true|false"}, status_code=400)
        scope = data.get("scope", "once")
        strong = data.get("strong") is True
        if scope not in SCOPES:
            return JSONResponse({"error": f"scope must be one of {SCOPES}"}, status_code=400)
        if strong:
            # Strong approval: the approver re-enters their own token for this decision.
            again = store.authenticate(data.get("token"))
            if again is None or again["name"] != person["name"]:
                return JSONResponse({"error": "Re-enter your token for strong approval"}, 403)
        try:
            result = store.resolve(
                request.path_params["request_id"],
                approved=data["approve"],
                approver=person["name"],
                scope=scope,
                minutes=data.get("minutes"),
                strong=strong,
                note=str(data.get("note") or ""),
            )
        except KeyError:
            return JSONResponse({"error": "Not found"}, status_code=404)
        except PermissionError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse(result)

    async def grants(request):
        if approver(request) is None:
            return unauthorized()
        return JSONResponse({"grants": store.list_grants(active_only=True)})

    async def revoke(request):
        person = approver(request, write=True)
        if person is None:
            return unauthorized()
        try:
            store.revoke_grant(request.path_params["grant_id"], by=person["name"])
        except KeyError:
            return JSONResponse({"error": "Not found or already revoked"}, status_code=404)
        return JSONResponse({"ok": True})

    async def events(request):
        if approver(request) is None:
            return unauthorized()
        loaded, error = cache.load()
        query = request.query_params
        selected = [e for e in reversed(loaded) if _matches(e, query)]
        offset = _int(query.get("offset"), 0, 0, 10**9)
        limit = _int(query.get("limit"), 100, 1, 1000)
        return JSONResponse(
            {
                "events": selected[offset : offset + limit],
                "total": len(selected),
                "verified_events": len(loaded),
                "verified": error is None,
                "error": error,
                "signatures_checked": audit_key is not None,
            }
        )

    async def event(request):
        if approver(request) is None:
            return unauthorized()
        loaded, _ = cache.load()
        wanted = request.path_params["event_id"]
        found = next((e for e in loaded if e.get("event_id") == wanted), None)
        if found is None:
            return JSONResponse({"error": "Not found"}, status_code=404)
        action_id = found.get("action_id")
        timeline = [e for e in loaded if action_id and e.get("action_id") == action_id]
        return JSONResponse({"event": found, "timeline": timeline})

    async def report(request):
        if approver(request) is None:
            return unauthorized()
        loaded, error = cache.load()
        dry_run_only = request.query_params.get("dry_run_only") in {"1", "true"}
        return JSONResponse({**build_report(loaded, dry_run_only=dry_run_only), "error": error})

    async def slack_actions(request):
        if not slack_signing_secret:
            return JSONResponse({"error": "Slack is not configured"}, status_code=404)
        raw = await request.body()
        if not slack.verify_slack_signature(
            slack_signing_secret,
            request.headers.get("x-slack-request-timestamp"),
            raw,
            request.headers.get("x-slack-signature"),
        ):
            return JSONResponse({"error": "Bad signature"}, status_code=401)
        text = slack.handle_action(store, raw)
        try:
            from urllib.parse import parse_qs

            response_url = json.loads(parse_qs(raw.decode())["payload"][0]).get("response_url")
        except (KeyError, ValueError):
            response_url = None
        if response_url:
            threading.Thread(
                target=_quietly, args=(slack.post_response, response_url, text), daemon=True
            ).start()
        return Response(status_code=200)

    routes = [
        *(Route(path, static) for path in STATIC),
        Route("/api/login", login, methods=["POST"]),
        Route("/api/logout", logout, methods=["POST"]),
        Route("/api/me", me),
        Route("/api/approvals", approvals),
        Route("/api/approvals/{request_id}", approval),
        Route("/api/approvals/{request_id}/decision", decide, methods=["POST"]),
        Route("/api/grants", grants),
        Route("/api/grants/{grant_id}/revoke", revoke, methods=["POST"]),
        Route("/api/events", events),
        Route("/api/events/{event_id}", event),
        Route("/api/report", report),
        Route("/slack/actions", slack_actions, methods=["POST"]),
    ]
    return Starlette(routes=routes, middleware=[Middleware(_SecurityHeaders)])


def _int(value, default, low, high):
    try:
        return min(max(int(value), low), high)
    except (TypeError, ValueError):
        return default


def _matches(event, query):
    for field, key in (("stage", "stage"), ("tool", "tool"), ("agent_id", "agent")):
        if query.get(key) and event.get(field) != query.get(key):
            return False
    decision = query.get("decision")
    if decision and (event.get("final_decision") or event.get("evaluated_decision")) != decision:
        return False
    text = (query.get("q") or "").strip().lower().replace("\\", "/")
    if not text:
        return True
    # Search Windows paths with either slash: JSON escapes each backslash as two.
    haystack = json.dumps(event, sort_keys=True).lower().replace("\\\\", "/")
    return text in haystack


def _quietly(function, *args):
    try:
        function(*args)
    except Exception:
        pass
