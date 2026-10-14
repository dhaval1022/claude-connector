"""In-process sliding-window rate limiting. Correct for a single server process; if you run
several workers/instances, move this state to a shared store (e.g. Redis)."""
import math
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from app.config import get_settings

_now = time.monotonic   # patched in tests


class RateLimited(ValueError):
    """Safe-to-display message; the caller should retry later."""


class SlidingWindow:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._ops = 0

    def hit(self, key: str, limit: int, window_s: float) -> float | None:
        """Record a hit. Returns None if allowed, else seconds until a slot frees up."""
        now = _now()
        q = self._hits[key]
        while q and q[0] <= now - window_s:
            q.popleft()
        self._ops += 1
        if self._ops % 2000 == 0:        # drop idle keys so memory stays bounded
            for k in [k for k, v in self._hits.items() if not v or v[-1] <= now - 3600]:
                del self._hits[k]
        if len(q) >= limit:
            return max(q[0] + window_s - now, 0.1)
        q.append(now)
        return None

    def reset(self):
        self._hits.clear()


LIMITER = SlidingWindow()


def enforce(bucket: str, key: str, limit: int, window_s: int) -> None:
    retry = LIMITER.hit(f"{bucket}:{key}", limit, window_s)
    if retry is not None:
        raise RateLimited(f"Rate limit exceeded for {bucket}: at most {limit} per "
                          f"{window_s}s. Retry in {math.ceil(retry)}s.")


def client_ip(request: Request) -> str:
    """Peer address; with trusted_proxy_count=N, the Nth-from-right X-Forwarded-For entry
    (the one added by YOUR proxy), so clients cannot spoof it."""
    n = get_settings().trusted_proxy_count
    if n > 0:
        hops = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",")
                if p.strip()]
        if len(hops) >= n:
            return hops[-n]
    return request.client.host if request.client else "unknown"


def ip_limit(bucket: str, setting: str):
    """FastAPI dependency: per-client-IP limit (per minute) read from settings at call time."""
    async def dep(request: Request):
        retry = LIMITER.hit(f"{bucket}:{client_ip(request)}", getattr(get_settings(), setting), 60)
        if retry is not None:
            raise HTTPException(429, "Too many requests. Slow down.",
                                headers={"Retry-After": str(math.ceil(retry))})
    return dep
