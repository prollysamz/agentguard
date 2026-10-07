# Sessions and rate limits

## One Guard, many agents

A Guard holds the shared configuration: tools, policy, audit log, approval provider and
judge. A **session** holds what belongs to one agent run: its lock, rate window, session
taint, denial history and halt flag.

```python
guard = Guard("policy.yaml", audit="agentguard.jsonl", approval=QueueApproval(store))
# ...register tools once with @guard.tool...

researcher = guard.new_session(agent_id="researcher")
writer = guard.new_session(agent_id="writer")

researcher.call("fetch", {"url": "https://docs.python.org/3/"})
await writer.acall("save_note", {"path": "notes.md", "content": "..."})
```

- Calls in **different sessions run in parallel**. Calls in one session are serialized.
- A secret seen by one session taints only that session. A failure halts only that session.
- Audit events carry each session's `session_id` and `agent_id`.

To route decorated tools and framework adapters to a session without passing it around,
bind it to the current context. Threads and asyncio tasks started inside inherit it:

```python
with researcher:
    agent.run("Summarize the asyncio docs")   # every guarded tool call uses researcher
```

Without a binding, calls use `guard.default_session`. `guard.session`, `guard.session_id`
and `guard.agent_id` describe the current session. `session.summary` counts its decisions;
`guard.summary` counts all of them.

## Rate limits

`limits.max_calls_per_minute` is enforced by a rate limiter, per scope:

```yaml
limits:
  max_calls_per_minute: 120
  rate_limit_scope: agent      # session (default) | agent | global
```

| Scope | Who shares the budget |
| --- | --- |
| `session` | Each session separately |
| `agent` | All sessions with the same `agent_id` |
| `global` | Every caller using the same limiter |

The default `LocalRateLimiter` is an in-process sliding window. To share limits across
processes and machines, use Redis:

```sh
pip install "agentguard-oss[redis]"
```

```python
import redis

from agentguard.core.ratelimit import RedisRateLimiter

limiter = RedisRateLimiter(redis.Redis.from_url("redis://localhost:6379/0"), prefix="prod:")
guard = Guard("policy.yaml", rate_limiter=limiter)
```

`RedisRateLimiter` counts every attempt in fixed one-minute windows, using atomic
`INCR` and `EXPIRE`. A burst can reach twice the limit across a window boundary. If Redis is
unreachable, calls are denied ("Rate limiter unavailable").

A custom limiter is any object with `hit(key, limit, window) -> bool`.
