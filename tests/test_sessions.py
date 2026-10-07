import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from agentguard import Guard, GuardDenied
from agentguard.audit.reader import read_log
from agentguard.core.ratelimit import LocalRateLimiter, RedisRateLimiter

RULES = [
    {"capability": "filesystem.read", "effect": "allow"},
    {"capability": "network.request", "effect": "allow"},
]


def policy(**limits):
    return {"version": 1, "rules": RULES, "limits": limits}


def test_sessions_run_in_parallel(make_guard):
    guard = make_guard(RULES)
    barrier = threading.Barrier(2, timeout=5)

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        barrier.wait()  # Only passes if both sessions are inside a call at once.
        return "ok"

    sessions = [guard.new_session(agent_id=f"agent-{n}") for n in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda s: s.call("read", {"path": "a.txt"}), sessions))
    assert results == ["ok", "ok"]


def test_calls_within_one_session_are_serialized(make_guard):
    guard = make_guard(RULES)
    active, peak, lock = 0, 0, threading.Lock()

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        threading.Event().wait(0.02)
        with lock:
            active -= 1
        return "ok"

    session = guard.new_session()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: session.call("read", {"path": "a.txt"}), range(8)))
    assert peak == 1


def test_session_state_is_isolated(make_guard):
    guard = make_guard(RULES)

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        if path.endswith("secret.txt"):
            return "ghp_" + "X" * 36
        if path.endswith("crash.txt"):
            raise RuntimeError("tool crashed")
        return "ok"

    @guard.tool(capability="network.request")
    def fetch(url: str):
        return "fetched"

    tainted, crashed, clean = (guard.new_session(agent_id=a) for a in ("a", "b", "c"))
    tainted.call("read", {"path": "secret.txt"})
    with pytest.raises(GuardDenied, match="sensitive data was observed"):
        tainted.call("fetch", {"url": "https://example.com"})
    with pytest.raises(Exception, match="session halted"):
        crashed.call("read", {"path": "crash.txt"})
    assert clean.call("fetch", {"url": "https://example.com"}) == "fetched"
    assert crashed.state.halted and not clean.state.halted and not guard.session.halted
    agents = {e["session_id"]: e["agent_id"] for e in read_log(guard.audit.path)}
    assert agents == {tainted.id: "a", crashed.id: "b", clean.id: "c"}


def test_with_session_routes_decorated_tools_and_tasks(make_guard):
    guard = make_guard(RULES)
    seen = []

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        seen.append(guard.session_id)
        return "ok"

    @guard.tool(capability="filesystem.read")
    async def aread(path: str):
        seen.append(guard.session_id)
        return "ok"

    session = guard.new_session(agent_id="worker")
    with session:
        read("a.txt")
        asyncio.run(aread("b.txt"))
        assert guard.agent_id == "worker"
    read("c.txt")
    assert seen == [session.id, session.id, guard.default_session.id]
    assert session.summary["allow"] == 2 and guard.summary["allow"] == 3


@pytest.mark.parametrize(
    "scope,agents,expected_allowed",
    [
        ("session", ["a", "a"], 4),  # Each session gets its own 2 calls.
        ("agent", ["a", "a"], 2),  # Same agent_id shares 2.
        ("agent", ["a", "b"], 4),
        ("global", ["a", "b"], 2),  # Everyone shares 2.
    ],
)
def test_rate_limit_scopes(make_guard, scope, agents, expected_allowed):
    guard = make_guard(policy=policy(max_calls_per_minute=2, rate_limit_scope=scope))

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        return "ok"

    allowed = 0
    for agent in agents:
        session = guard.new_session(agent_id=agent)
        for _ in range(3):
            try:
                session.call("read", {"path": "a.txt"})
                allowed += 1
            except GuardDenied as exc:
                assert "rate limit" in str(exc)
    assert allowed == expected_allowed


def test_redis_limit_is_shared_between_guards(tmp_path):
    fakeredis = pytest.importorskip("fakeredis")
    server = fakeredis.FakeServer()

    def worker(n):
        # Separate Guards and clients, as in separate processes, sharing one Redis.
        limiter = RedisRateLimiter(fakeredis.FakeRedis(server=server), prefix="test:")
        guard = Guard(
            policy(max_calls_per_minute=3, rate_limit_scope="global"),
            audit=tmp_path / f"audit-{n}.jsonl",
            context={"working_directory": str(tmp_path)},
            rate_limiter=limiter,
        )

        @guard.tool(capability="filesystem.read")
        def read(path: str):
            return "ok"

        return guard

    guards = [worker(n) for n in range(2)]
    allowed = 0
    for guard in guards:
        for _ in range(3):
            try:
                guard.call("read", {"path": "a.txt"})
                allowed += 1
            except GuardDenied:
                pass
    assert allowed == 3


def test_rate_limiter_failure_denies(make_guard):
    class Down:
        def hit(self, key, limit, window):
            raise ConnectionError("redis down")

    guard = make_guard(RULES, rate_limiter=Down())

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        pytest.fail("Call ran without a rate-limit decision")

    with pytest.raises(GuardDenied, match="Rate limiter unavailable"):
        read("a.txt")


def test_local_rate_limiter_window():
    limiter = LocalRateLimiter()
    assert [limiter.hit("k", 2, window=0.05) for _ in range(3)] == [True, True, False]
    threading.Event().wait(0.06)
    assert limiter.hit("k", 2, window=0.05)
