import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from agentguard import GuardDenied, GuardError
from agentguard.approval import Approval
from agentguard.audit.reader import read_log
from agentguard.risk.scorer import Risk


def rule(cap="filesystem.read", effect="allow", **conditions):
    return {"capability": cap, "effect": effect, **conditions}


def test_allow_normalizes_and_audits_lifecycle(make_guard, tmp_path):
    guard = make_guard([rule(paths=[str(tmp_path / "**")])])
    reached = []

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        reached.append(path)
        return "hello"

    assert read_file("a/../README.md") == "hello"
    # Tools get the requested absolute path; policy matched its resolved target.
    assert Path(reached[0]).is_absolute()
    assert Path(reached[0]).resolve() == (tmp_path / "README.md").resolve()
    events = read_log(guard.audit.path)
    assert [e["stage"] for e in events] == [
        "proposed",
        "authorized",
        "executing",
        "executed",
        "observed",
    ]
    assert len({e["action_id"] for e in events}) == 1
    assert events[-1]["verification"]["status"] == "not_configured"


@pytest.mark.parametrize(
    "arguments",
    [{}, {"path": 3}, {"path": "ok", "extra": 1}, {"path": "\x00"}, [], {"path": "x" * 70000}],
)
def test_bad_arguments_never_execute(make_guard, arguments):
    guard = make_guard([rule()])

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        pytest.fail("Malformed request reached tool")

    with pytest.raises(GuardDenied):
        guard.call("read_file", arguments)
    assert read_log(guard.audit.path)[-1]["stage"] == "rejected"


def test_unknown_tool_and_capability(make_guard):
    guard = make_guard()
    with pytest.raises(GuardDenied):
        guard.call("missing", {})
    with pytest.raises(ValueError):
        guard.tool(capability="unknown")
    with pytest.raises(ValueError):
        guard.tool(capability="shell.execute", sandboxed=True)


def test_decorator_bind_failure_is_audited(make_guard):
    guard = make_guard()

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        pytest.fail("Invalid call reached tool")

    with pytest.raises(GuardDenied):
        read_file()
    assert read_log(guard.audit.path)[-1]["final_decision"] == "deny"


def test_deny_overrides_allow_and_no_approval_can_override(make_guard):
    class Provider:
        def request(self, action, decision):
            pytest.fail("DENY must never request approval")

    guard = make_guard([rule(), rule(effect="deny")], approval=Provider())

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        pytest.fail("Denied tool executed")

    with pytest.raises(GuardDenied):
        read_file("README.md")


@pytest.mark.parametrize(
    "answer", [Approval(False), True, None, Approval(True), Approval(True, "alice")]
)
def test_approval_must_be_explicit_and_attributed(make_guard, answer):
    class Provider:
        def request(self, action, decision):
            return answer

    guard = make_guard([rule(effect="ask")], approval=Provider())
    reached = []

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        reached.append(path)
        return "ok"

    if answer == Approval(True, "alice"):
        assert read_file("README.md") == "ok"
    else:
        with pytest.raises(GuardDenied):
            read_file("README.md")
        assert not reached


def test_approval_timeout_and_mutation_do_not_authorize(make_guard):
    class Slow:
        def request(self, action, decision):
            time.sleep(0.1)
            return Approval(True, "alice")

    guard = make_guard([rule(effect="ask")], approval=Slow(), approval_timeout=0.01)

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        pytest.fail("Late approval reached tool")

    with pytest.raises(GuardDenied):
        read_file("README.md")
    time.sleep(0.12)
    assert read_log(guard.audit.path)[-1]["stage"] == "denied"


def test_approval_receives_snapshot(make_guard):
    class Mutator:
        def request(self, action, decision):
            action.arguments["path"] = "stolen"
            return Approval(True, "alice")

    guard = make_guard([rule(effect="ask")], approval=Mutator())

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        return path

    assert "stolen" not in read_file("README.md")


def test_provider_failure_denies(make_guard):
    class Broken:
        def request(self, action, decision):
            raise RuntimeError("offline")

    guard = make_guard([rule(effect="ask")], approval=Broken())

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        pytest.fail("Broken approval executed")

    with pytest.raises(GuardDenied):
        read_file("README.md")


@pytest.mark.parametrize("strong", [False, True])
def test_strong_approval(make_guard, strong):
    class Provider:
        def request(self, action, decision):
            return Approval(True, "alice", strong=strong)

    class Judge:
        def evaluate(self, action):
            return Risk(80, ("High risk",))

    guard = make_guard([rule()], approval=Provider(), judge=Judge())

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        return "ok"

    if strong:
        assert read_file("README.md") == "ok"
    else:
        with pytest.raises(GuardDenied):
            read_file("README.md")


def test_dry_run_executes_but_preserves_would_deny(make_guard):
    guard = make_guard(mode="dry-run")

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        return "executed"

    assert read_file("README.md") == "executed"
    events = read_log(guard.audit.path)
    assert events[1]["dry_run_override"] is True
    assert events[1]["evaluated_decision"] == "deny"
    assert guard.summary == {"allow": 0, "ask": 0, "deny": 1}


@pytest.mark.parametrize("mode", ["enforce", "dry-run"])
def test_engine_failure_is_closed(make_guard, monkeypatch, mode):
    guard = make_guard([rule()], mode=mode)
    monkeypatch.setattr(guard.engine, "evaluate", lambda _: 1 / 0)

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        pytest.fail("Engine failure reached tool")

    with pytest.raises(GuardDenied):
        read_file("README.md")


def test_async_uses_shared_pipeline(make_guard):
    guard = make_guard([rule()])

    @guard.tool(capability="filesystem.read")
    async def read_file(path: str):
        return "async result"

    assert asyncio.run(read_file("README.md")) == "async result"
    assert read_log(guard.audit.path)[-1]["stage"] == "observed"


def test_tool_failure_halts_session_and_does_not_log_exception_payload(make_guard):
    guard = make_guard([rule()])

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        raise ValueError("secret-sensitive-exception")

    with pytest.raises(GuardError, match="session halted"):
        read_file("README.md")
    with pytest.raises(GuardDenied, match="Session halted"):
        read_file("README.md")
    assert "secret-sensitive-exception" not in guard.audit.path.read_text()


def test_rate_limit(make_guard):
    guard = make_guard(
        policy={"version": 1, "rules": [rule()], "limits": {"max_calls_per_minute": 1}}
    )

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        return "ok"

    read_file("README.md")
    with pytest.raises(GuardDenied, match="rate limit"):
        read_file("README.md")


def test_sync_call_of_async_tool_inside_event_loop(make_guard):
    guard = make_guard([rule()])

    @guard.tool(capability="filesystem.read")
    async def read_file(path: str) -> str:
        await asyncio.sleep(0)
        return "async result"

    async def main():
        return guard.call("read_file", {"path": "README.md"})

    assert asyncio.run(main()) == "async result"
    assert not guard.session.halted


def test_audit_keeps_action_timestamp(make_guard):
    guard = make_guard([rule()])

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        return "ok"

    read_file("README.md")
    events = read_log(guard.audit.path)
    assert len({e["action_timestamp"] for e in events}) == 1
    assert all(e["action_timestamp"] <= e["timestamp"] for e in events)


def test_nested_guarded_calls_do_not_deadlock(make_guard):
    guard = make_guard([rule()])

    @guard.tool(capability="filesystem.read")
    async def inner(path: str) -> str:
        return "inner"

    @guard.tool(capability="filesystem.read")
    def inner_sync(path: str) -> str:
        return "inner sync"

    @guard.tool(capability="filesystem.read")
    async def outer(path: str) -> str:
        return await inner(path) + " / " + inner_sync(path)

    async def main():
        # Both the async path and a sync call made inside a running event loop.
        return await outer("README.md"), guard.call("outer", {"path": "README.md"})

    # Don't wait on the worker at exit, so a deadlock regression fails instead of hanging.
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(asyncio.run, main())
        assert future.result(timeout=10) == ("inner / inner sync", "inner / inner sync")
    finally:
        pool.shutdown(wait=False)
    stages = [e["stage"] for e in read_log(guard.audit.path) if e["stage"] == "observed"]
    assert len(stages) == 6
