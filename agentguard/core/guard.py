import asyncio
import contextvars
import inspect
import json
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_type_hints
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import TypeAdapter

from agentguard.approval.base import Approval, request_bounded
from agentguard.audit.logger import AuditLogger
from agentguard.core.action import Action, Context
from agentguard.core.context import SessionRiskContext
from agentguard.core.decision import (
    ApprovalPending,
    Decision,
    Effect,
    GuardDenied,
    GuardError,
)
from agentguard.core.ratelimit import LocalRateLimiter
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.explain import combine
from agentguard.policy.loader import load_policy
from agentguard.policy.matcher import absolute_path, resolve_path
from agentguard.risk.scorer import Risk, score
from agentguard.risk.secrets import detect_secrets


@dataclass
class Tool:
    function: object
    signature: inspect.Signature
    validators: dict
    capability: str
    executor: object = None
    verifier: object = None
    # Canonical argument name ("path", "url", "cmd", "content") -> the tool's parameter.
    roles: dict = field(default_factory=dict)
    recipients: tuple = ()


RECIPIENT_FIELDS = ("to", "cc", "bcc", "recipient", "recipients")
ROLE_ARGUMENTS = ("path", "url", "cmd", "content")
# Sessions whose call() is running in this context, so tools can make nested guarded calls.
_ACTIVE_SESSIONS = contextvars.ContextVar("agentguard_active_sessions", default=frozenset())
# Sessions bound with ``with guard.new_session(...)``, keyed by Guard.
_BOUND_SESSIONS = contextvars.ContextVar("agentguard_bound_sessions", default=None)
# Reset tokens for nested ``with session:`` blocks, kept per context (thread or task),
# because one Session object may be entered from many threads at once.
_BINDING_TOKENS = contextvars.ContextVar("agentguard_binding_tokens", default=())


def _recipient_count(arguments, fields=RECIPIENT_FIELDS):
    count = 0
    for key in fields:
        value = arguments.get(key)
        if value is None:
            continue
        items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
        count += sum(1 for item in items if str(item).strip())
    return count


def _argument_roles(capability, parameters, mapped, recipient_args):
    """Validate role mappings at registration so misconfigured tools fail early."""
    roles = {}
    for canonical, parameter in mapped.items():
        if parameter is None or parameter == canonical:
            continue
        if parameter not in parameters:
            raise ValueError(f"{canonical} argument {parameter!r} is not a tool parameter")
        if canonical in parameters:
            raise ValueError(f"Cannot map {parameter!r} to {canonical!r}: both are parameters")
        roles[canonical] = parameter

    def has(canonical):
        return canonical in roles or canonical in parameters

    if capability.startswith("filesystem.") and not has("path"):
        raise ValueError("Filesystem tools need a path parameter; set path_arg=")
    if capability == "network.request" and not has("url"):
        raise ValueError("Network tools need a url parameter; set url_arg=")
    if capability in {"shell.execute", "repository.write"} and not (
        has("cmd") or "command" in parameters
    ):
        raise ValueError("Command tools need a cmd or command parameter; set command_arg=")
    if recipient_args is None:
        recipients = tuple(f for f in RECIPIENT_FIELDS if f in parameters)
    else:
        recipients = tuple(recipient_args)
        missing = [f for f in recipients if f not in parameters]
        if missing:
            raise ValueError(f"Recipient arguments are not tool parameters: {missing}")
    return roles, recipients


def _run_coroutine(coroutine):
    """Run an async tool from synchronous call(), even inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    with ThreadPoolExecutor(max_workers=1) as pool:
        context = contextvars.copy_context()
        return pool.submit(context.run, asyncio.run, coroutine).result()


class Session:
    """One agent session: its own lock, rate window, taint and halt state.

    Create with ``guard.new_session(agent_id=...)``. Calls on different sessions run in
    parallel; calls within one session are serialized. ``with session:`` routes guarded
    tools called in that context (threads and tasks started from it included) here.
    """

    def __init__(self, guard, agent_id):
        self.guard = guard
        self.id = "session_" + uuid4().hex
        self.agent_id = agent_id
        self.state = SessionRiskContext()
        self.lock = threading.RLock()
        self.counts = Counter()

    @property
    def summary(self):
        return {effect.value: self.counts[effect.value] for effect in Effect}

    def call(self, name, arguments):
        with self:
            return self.guard.call(name, arguments)

    async def acall(self, name, arguments):
        with self:
            return await self.guard.acall(name, arguments)

    def __enter__(self):
        bound = dict(_BOUND_SESSIONS.get() or {})
        bound[id(self.guard)] = self
        token = _BOUND_SESSIONS.set(bound)
        _BINDING_TOKENS.set((*_BINDING_TOKENS.get(), token))
        return self

    def __exit__(self, *exc):
        *rest, token = _BINDING_TOKENS.get()
        _BINDING_TOKENS.set(tuple(rest))
        _BOUND_SESSIONS.reset(token)


class Guard:
    def __init__(
        self,
        policy,
        audit="agentguard.jsonl",
        *,
        mode="enforce",
        agent_id="python-agent",
        context=None,
        approval=None,
        approval_timeout=30.0,
        judge=None,
        rate_limiter=None,
    ):
        if mode not in {"enforce", "dry-run"}:
            raise ValueError("mode must be enforce or dry-run")
        if approval_timeout <= 0:
            raise ValueError("approval_timeout must be positive")
        self.policy = load_policy(policy)
        self.engine = PolicyEngine(self.policy)
        self.audit = audit if isinstance(audit, AuditLogger) else AuditLogger(audit)
        self.mode = mode
        self.context = Context.model_validate(context or {"working_directory": str(Path.cwd())})
        self.context = self.context.model_copy(
            update={
                "working_directory": str(Path(self.context.working_directory).resolve(strict=True))
            }
        )
        self.approval, self.approval_timeout, self.judge = approval, approval_timeout, judge
        self.rate_limiter = rate_limiter or LocalRateLimiter()
        self._tools = {}
        self._counts = Counter()
        self._counts_lock = threading.Lock()
        self.default_session = Session(self, agent_id)

    def new_session(self, agent_id=None):
        """A new session sharing this Guard's tools, policy, audit, approval and judge."""
        return Session(self, agent_id or self.default_session.agent_id)

    def _current(self):
        bound = _BOUND_SESSIONS.get()
        return (bound or {}).get(id(self), self.default_session)

    @property
    def agent_id(self):
        return self._current().agent_id

    @property
    def session_id(self):
        return self._current().id

    @property
    def session(self):
        """The current session's risk state (taint, denials, halt flag)."""
        return self._current().state

    def _count(self, session, effect):
        with self._counts_lock:
            self._counts[effect] += 1
        session.counts[effect] += 1

    @property
    def capabilities(self):
        """Built-in capabilities plus any the policy declares."""
        return self.policy.all_capabilities

    @property
    def tools(self):
        """Registered tool names, for building model-facing tool lists and schemas."""
        return tuple(self._tools)

    @property
    def summary(self):
        """Evaluated decisions across all sessions."""
        return {effect.value: self._counts[effect.value] for effect in Effect}

    def tool(
        self,
        *,
        capability,
        name=None,
        sandboxed=False,
        executor=None,
        verifier=None,
        path_arg=None,
        url_arg=None,
        command_arg=None,
        content_arg=None,
        recipient_args=None,
    ):
        """Register a tool. *_arg name the parameter that plays each role when it is not
        called path, url, cmd/command or content; recipient_args lists recipient fields."""
        if capability not in self.capabilities:
            raise ValueError(
                f"Unsupported capability {capability!r}; declare custom ones in the policy"
            )
        if sandboxed and executor is None:
            raise ValueError("sandboxed=True requires an explicit controlled executor")
        if executor is not None and capability not in executor.capabilities:
            raise ValueError("Executor does not support capability")

        def decorate(function):
            tool_name = name or function.__name__
            if tool_name in self._tools:
                raise ValueError("Duplicate tool registration")
            signature = inspect.signature(function)
            hints = get_type_hints(function)
            validators = {}
            for key, param in signature.parameters.items():
                if param.kind in {param.VAR_POSITIONAL, param.VAR_KEYWORD, param.POSITIONAL_ONLY}:
                    raise ValueError(
                        "Tool parameters must be explicit keyword-compatible parameters"
                    )
                if key not in hints:
                    raise ValueError(f"Missing type annotation: {key}")
                validators[key] = TypeAdapter(hints[key])
            roles, recipients = _argument_roles(
                capability,
                signature.parameters,
                {"path": path_arg, "url": url_arg, "cmd": command_arg, "content": content_arg},
                recipient_args,
            )
            self._tools[tool_name] = Tool(
                function, signature, validators, capability, executor, verifier, roles, recipients
            )

            def normalize_args(args, kwargs):
                try:
                    bound = signature.bind(*args, **kwargs)
                    bound.apply_defaults()
                    return dict(bound.arguments)
                except TypeError:
                    self._reject_malformed(
                        self._current(), tool_name, capability, "Invalid tool argument structure"
                    )

            if inspect.iscoroutinefunction(function):

                async def wrapper(*args, **kwargs):
                    return await self.acall(tool_name, normalize_args(args, kwargs))
            else:

                def wrapper(*args, **kwargs):
                    return self.call(tool_name, normalize_args(args, kwargs))

            # Preserve schema metadata without exposing a convenient __wrapped__ bypass.
            wrapper.__name__, wrapper.__doc__ = tool_name, function.__doc__
            wrapper.__annotations__ = hints
            wrapper.__signature__ = signature.replace(
                parameters=[
                    p.replace(annotation=hints[p.name]) for p in signature.parameters.values()
                ],
                return_annotation=hints.get("return", inspect.Signature.empty),
            )
            return wrapper

        return decorate

    def _reject_malformed(self, session, tool, capability, reason):
        decision = Decision(Effect.DENY, Effect.DENY, 100, (reason,))
        self._count(session, "deny")
        self.audit.append(
            {
                "stage": "rejected",
                "agent_id": session.agent_id,
                "session_id": session.id,
                "tool": str(tool)[:200],
                "capability": capability,
                "final_decision": "deny",
                "risk_score": 100,
                "reasons": [reason],
                "execution_status": "not_executed",
            }
        )
        raise GuardDenied(decision)

    def _normalize(self, session, name, arguments, tool):
        if type(arguments) is not dict:
            raise ValueError("Arguments must be a JSON object")
        # Enforce JSON transport semantics, bounded size, and no NaN/custom objects.
        encoded = json.dumps(arguments, allow_nan=False)
        if len(encoded.encode()) > self.policy.limits.max_argument_bytes:
            raise ValueError("Request too large")
        arguments = json.loads(encoded)
        bound = tool.signature.bind(**arguments)
        bound.apply_defaults()
        arguments = {
            key: tool.validators[key].validate_python(value, strict=True)
            for key, value in bound.arguments.items()
        }
        # Present role arguments under canonical names to policy, risk and executors.
        for canonical, parameter in tool.roles.items():
            arguments[canonical] = arguments.pop(parameter)
        cap = tool.capability
        if cap.startswith("filesystem."):
            # Policy and risk match the resolved target; execution gets the requested path.
            resolve_path(arguments["path"], self.context.working_directory)
            arguments["path"] = absolute_path(arguments["path"], self.context.working_directory)
        if cap == "network.request":
            url = arguments["url"]
            if type(url) is not str or any(ord(c) <= 32 for c in url) or "\\" in url:
                raise ValueError("Invalid URL")
            parsed = urlsplit(url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError("Invalid URL")
            _ = parsed.port  # Reject malformed ports before policy matching.
        if cap in {"shell.execute", "repository.write"}:
            command = arguments.get("cmd", arguments.get("command"))
            if type(command) is not str or not command.strip() or "\x00" in command:
                raise ValueError("Missing or invalid command")
        if cap in {"email.send", "message.send"}:
            count = _recipient_count(arguments, tool.recipients)
            if count > self.policy.limits.max_recipients_per_action:
                raise ValueError("Too many recipients")
        return Action(
            agent_id=session.agent_id,
            session_id=session.id,
            tool=name,
            capability=cap,
            arguments=arguments,
            context=self.context,
        )

    def _evaluate(self, session, action):
        policy_result, policy_reason = self.engine.evaluate(action)
        risk = score(action, session.state, self.policy.capabilities)
        reasons = [policy_reason, *risk.reasons]
        judged = getattr(self.judge, "capabilities", None)
        if (
            self.judge is not None
            and policy_result != Effect.DENY
            and not risk.hard_deny
            and (judged is None or action.capability in judged)
        ):
            try:
                semantic = self.judge.evaluate(action.model_copy(deep=True))
                if (
                    not isinstance(semantic, Risk)
                    or type(semantic.score) is not int
                    or not 0 <= semantic.score <= 100
                ):
                    raise ValueError("Invalid semantic risk")
                # Model verdicts are fallible: a judge "deny" escalates to human approval,
                # while a judge score at or above the deny threshold still denies.
                floor = self.policy.risk.ask if semantic.hard_deny is True else 0
                risk = Risk(max(risk.score, semantic.score, floor), (), risk.hard_deny)
                reasons.extend(semantic.reasons)
                if floor:
                    reasons.append("Semantic judge flagged this action; human approval required")
            except Exception:
                reasons.append("Semantic judge unavailable; deterministic evaluation retained")
        effect, strong = combine(self.policy, policy_result, risk)
        return Decision(effect, policy_result, risk.score, tuple(reasons), strong)

    def _event(self, action, decision, stage, **extra):
        data = action.model_dump()
        # The logger stamps each event; keep the proposal time under its own key.
        data["action_timestamp"] = data.pop("timestamp")
        return self.audit.append(
            {
                **data,
                "action_id": action.id,
                "stage": stage,
                "mode": self.mode,
                "policy_result": decision.policy_result.value,
                "risk_score": decision.risk_score,
                "evaluated_decision": decision.effect.value,
                "reasons": list(decision.reasons),
                **extra,
            }
        )

    async def acall(self, name, arguments):
        """Offload the serialized pipeline; cancellation cannot undo an executing tool."""
        if self._current() in _ACTIVE_SESSIONS.get():
            # Nested inside one of this session's tools: run inline under the held lock.
            return self.call(name, arguments)
        return await asyncio.to_thread(self.call, name, arguments)

    def call(self, name, arguments):
        session = self._current()
        if session in _ACTIVE_SESSIONS.get():
            # A tool this session is executing made a nested call; the outer call holds the lock.
            return self._dispatch(session, name, arguments)
        with session.lock:
            token = _ACTIVE_SESSIONS.set(_ACTIVE_SESSIONS.get() | {session})
            try:
                return self._dispatch(session, name, arguments)
            finally:
                _ACTIVE_SESSIONS.reset(token)

    def _rate_key(self, session):
        scope = self.policy.limits.rate_limit_scope
        return {"session": f"session:{session.id}", "agent": f"agent:{session.agent_id}"}.get(
            scope, "global"
        )

    def _dispatch(self, session, name, arguments):
        if not isinstance(name, str) or name not in self._tools:
            return self._reject_malformed(session, name, "unknown", "Unknown tool")
        tool = self._tools[name]
        if session.state.halted:
            return self._reject_malformed(
                session,
                name,
                tool.capability,
                "Session halted after execution or verification failure",
            )
        try:
            action = self._normalize(session, name, arguments, tool)
        except Exception:
            return self._reject_malformed(
                session, name, tool.capability, "Invalid or oversized tool arguments"
            )
        evaluation_failed = False
        try:
            within_limit = self.rate_limiter.hit(
                self._rate_key(session), self.policy.limits.max_calls_per_minute, 60.0
            )
        except Exception:
            within_limit, evaluation_failed = False, True
        if not within_limit:
            reason = "Rate limiter unavailable" if evaluation_failed else "Tool rate limit reached"
            decision = Decision(Effect.DENY, Effect.DENY, 100, (reason,))
        else:
            try:
                decision = self._evaluate(session, action)
            except Exception:
                evaluation_failed = True
                decision = Decision(
                    Effect.DENY, Effect.DENY, 100, ("Policy or risk evaluation failed",)
                )
        self._count(session, decision.effect.value)
        self._event(action, decision, "proposed", execution_status="not_executed")
        approval = Approval(False)
        allowed = decision.effect == Effect.ALLOW
        if self.mode == "dry-run" and not evaluation_failed:
            allowed = True
        elif decision.effect == Effect.ASK and self.approval is not None:
            approval = request_bounded(self.approval, action, decision, self.approval_timeout)
            allowed = approval.approved
        if not allowed:
            reasons = decision.reasons
            if approval.pending_id:
                reasons += (f"Awaiting human approval (request {approval.pending_id})",)
                pending = Decision(
                    Effect.DENY, decision.policy_result, decision.risk_score, reasons
                )
                self._event(
                    action,
                    pending,
                    "denied",
                    final_decision="deny",
                    execution_status="not_executed",
                    approval_request_id=approval.pending_id,
                    approval_status="pending",
                )
                raise ApprovalPending(pending, approval.pending_id)
            session.state.denied_actions.append(action.id)
            if decision.effect == Effect.ASK:
                reasons += ("Approval rejected, unavailable, insufficient, or timed out",)
            denied = Decision(Effect.DENY, decision.policy_result, decision.risk_score, reasons)
            self._event(
                action, denied, "denied", final_decision="deny", execution_status="not_executed"
            )
            raise GuardDenied(denied)
        self._event(
            action,
            decision,
            "authorized",
            final_decision="allow",
            approved_by=approval.approved_by if approval.approved else None,
            execution_status="pending",
            dry_run_override=self.mode == "dry-run",
        )
        try:
            before = tool.verifier.before(action.model_copy(deep=True)) if tool.verifier else None
            self._event(
                action,
                decision,
                "executing",
                final_decision="allow",
                execution_status="started",
            )
            execution_action = action.model_copy(deep=True)
            if tool.executor is not None:
                result = tool.executor.execute(execution_action)
            else:
                result = tool.function(
                    **{tool.roles.get(k, k): v for k, v in execution_action.arguments.items()}
                )
                if inspect.isawaitable(result):
                    result = _run_coroutine(result)
            self._event(
                action, decision, "executed", final_decision="allow", execution_status="success"
            )
            verification = (
                tool.verifier.after(action.model_copy(deep=True), before, result)
                if tool.verifier
                else {"status": "not_configured"}
            )
            session.state.sensitive_data_seen.update(detect_secrets(result))
            session.state.cumulative_risk += decision.risk_score
            if action.capability.startswith("filesystem."):
                session.state.files_accessed.append(action.arguments["path"])
            if action.capability == "network.request":
                session.state.domains_contacted.append(urlsplit(action.arguments["url"]).hostname)
            self._event(
                action,
                decision,
                "observed",
                final_decision="allow",
                execution_status="success",
                verification=verification,
                result_type=type(result).__name__,
                sensitive_result=bool(detect_secrets(result)),
            )
            return result
        except Exception as exc:
            session.state.halted = True
            # Avoid recording arbitrary exception strings which may contain credentials.
            self._event(
                action,
                decision,
                "failed",
                final_decision="deny",
                execution_status="failed",
                error_type=type(exc).__name__,
                session_halted=True,
            )
            raise GuardError(
                "Execution or verification failed; session halted (action may have had effects)"
            ) from exc
