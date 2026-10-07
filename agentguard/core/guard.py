import asyncio
import inspect
import json
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import get_type_hints
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import TypeAdapter

from agentguard.approval.base import Approval, request_bounded
from agentguard.audit.logger import AuditLogger
from agentguard.core.action import CAPABILITIES, Action, Context
from agentguard.core.context import SessionRiskContext
from agentguard.core.decision import Decision, Effect, GuardDenied, GuardError
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.loader import load_policy
from agentguard.policy.matcher import resolve_path
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


def _run_coroutine(coroutine):
    """Run an async tool from synchronous call(), even inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


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
    ):
        if mode not in {"enforce", "dry-run"}:
            raise ValueError("mode must be enforce or dry-run")
        if approval_timeout <= 0:
            raise ValueError("approval_timeout must be positive")
        self.policy = load_policy(policy)
        self.engine = PolicyEngine(self.policy)
        self.audit = AuditLogger(audit)
        self.mode, self.agent_id = mode, agent_id
        self.context = Context.model_validate(context or {"working_directory": str(Path.cwd())})
        self.context = self.context.model_copy(
            update={
                "working_directory": str(Path(self.context.working_directory).resolve(strict=True))
            }
        )
        self.session_id = "session_" + uuid4().hex
        self.session = SessionRiskContext()
        self.approval, self.approval_timeout, self.judge = approval, approval_timeout, judge
        self._tools = {}
        self._lock = threading.RLock()
        self._calls = deque()
        self._counts = Counter()

    @property
    def tools(self):
        """Registered tool names, for building model-facing tool lists and schemas."""
        return tuple(self._tools)

    @property
    def summary(self):
        return {effect.value: self._counts[effect.value] for effect in Effect}

    def tool(self, *, capability, name=None, sandboxed=False, executor=None, verifier=None):
        if capability not in CAPABILITIES:
            raise ValueError("Unsupported capability")
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
            self._tools[tool_name] = Tool(
                function, signature, validators, capability, executor, verifier
            )

            def normalize_args(args, kwargs):
                try:
                    bound = signature.bind(*args, **kwargs)
                    bound.apply_defaults()
                    return dict(bound.arguments)
                except TypeError:
                    self._reject_malformed(tool_name, capability, "Invalid tool argument structure")

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

    def _reject_malformed(self, tool, capability, reason):
        decision = Decision(Effect.DENY, Effect.DENY, 100, (reason,))
        self._counts["deny"] += 1
        self.audit.append(
            {
                "stage": "rejected",
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "tool": str(tool)[:200],
                "capability": capability,
                "final_decision": "deny",
                "risk_score": 100,
                "reasons": [reason],
                "execution_status": "not_executed",
            }
        )
        raise GuardDenied(decision)

    def _normalize(self, name, arguments, tool):
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
        cap = tool.capability
        if cap.startswith("filesystem."):
            arguments["path"] = resolve_path(arguments["path"], self.context.working_directory)
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
        if cap == "email.send":
            recipients = arguments.get("to", arguments.get("recipient", []))
            count = (
                len(recipients)
                if isinstance(recipients, list)
                else len(str(recipients).replace(";", ",").split(","))
            )
            if count > self.policy.limits.max_recipients_per_action:
                raise ValueError("Too many recipients")
        return Action(
            agent_id=self.agent_id,
            session_id=self.session_id,
            tool=name,
            capability=cap,
            arguments=arguments,
            context=self.context,
        )

    def _evaluate(self, action):
        policy_result, policy_reason = self.engine.evaluate(action)
        risk = score(action, self.session)
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
        effect = policy_result
        if risk.hard_deny or risk.score >= self.policy.risk.deny:
            effect = Effect.DENY
        elif effect != Effect.DENY and risk.score >= self.policy.risk.ask:
            effect = Effect.ASK
        return Decision(
            effect, policy_result, risk.score, tuple(reasons), risk.score >= self.policy.risk.strong
        )

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
        return await asyncio.to_thread(self.call, name, arguments)

    def call(self, name, arguments):
        with self._lock:
            if not isinstance(name, str) or name not in self._tools:
                return self._reject_malformed(name, "unknown", "Unknown tool")
            tool = self._tools[name]
            if self.session.halted:
                return self._reject_malformed(
                    name, tool.capability, "Session halted after execution or verification failure"
                )
            try:
                action = self._normalize(name, arguments, tool)
            except Exception:
                return self._reject_malformed(
                    name, tool.capability, "Invalid or oversized tool arguments"
                )
            now = time.monotonic()
            evaluation_failed = False
            while self._calls and self._calls[0] <= now - 60:
                self._calls.popleft()
            if len(self._calls) >= self.policy.limits.max_calls_per_minute:
                decision = Decision(
                    Effect.DENY, Effect.DENY, 100, ("Session tool rate limit reached",)
                )
            else:
                self._calls.append(now)
                try:
                    decision = self._evaluate(action)
                except Exception:
                    evaluation_failed = True
                    decision = Decision(
                        Effect.DENY, Effect.DENY, 100, ("Policy or risk evaluation failed",)
                    )
            self._counts[decision.effect.value] += 1
            self._event(action, decision, "proposed", execution_status="not_executed")
            approval = Approval(False)
            allowed = decision.effect == Effect.ALLOW
            if self.mode == "dry-run" and not evaluation_failed:
                allowed = True
            elif decision.effect == Effect.ASK and self.approval is not None:
                approval = request_bounded(self.approval, action, decision, self.approval_timeout)
                allowed = approval.approved
            if not allowed:
                self.session.denied_actions.append(action.id)
                reasons = decision.reasons
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
                before = (
                    tool.verifier.before(action.model_copy(deep=True)) if tool.verifier else None
                )
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
                    result = tool.function(**execution_action.arguments)
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
                self.session.sensitive_data_seen.update(detect_secrets(result))
                self.session.cumulative_risk += decision.risk_score
                if action.capability.startswith("filesystem."):
                    self.session.files_accessed.append(action.arguments["path"])
                if action.capability == "network.request":
                    self.session.domains_contacted.append(
                        urlsplit(action.arguments["url"]).hostname
                    )
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
                self.session.halted = True
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
