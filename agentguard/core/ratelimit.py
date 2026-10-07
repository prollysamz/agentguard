"""Call-rate limiters. A Guard asks ``hit(key, limit, window)`` before evaluating a call."""

import threading
import time
from collections import defaultdict, deque


class LocalRateLimiter:
    """In-process sliding window. Only allowed calls count toward the limit."""

    def __init__(self):
        self._calls = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            calls = self._calls[key]
            while calls and calls[0] <= now - window:
                calls.popleft()
            if len(calls) >= limit:
                return False
            calls.append(now)
            return True


class RedisRateLimiter:
    """Shared limit across processes and hosts, in fixed windows (atomic INCR + EXPIRE).

    Every attempt in a window counts, including denied ones, and a burst can reach up to
    twice the limit across a window boundary. ``client`` is a ``redis.Redis`` instance.
    Redis errors propagate, and the Guard then denies the call.
    """

    def __init__(self, client, prefix="agentguard:rate:"):
        self.client, self.prefix = client, prefix

    def hit(self, key: str, limit: int, window: float = 60.0) -> bool:
        bucket = int(time.time() // window)
        name = f"{self.prefix}{key}:{bucket}"
        pipeline = self.client.pipeline(transaction=True)
        pipeline.incr(name)
        pipeline.expire(name, int(window) + 1)
        count, _ = pipeline.execute()
        return int(count) <= limit
