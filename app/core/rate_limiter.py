"""
Token-bucket rate limiter.
Uses Redis when available; falls back to an in-process dict for development.
"""

import logging
import time
from collections import defaultdict
from typing import Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Sliding-window rate limiter.
    Each (IP, route-prefix) pair gets its own counter.
    Returns (allowed: bool, retry_after: int seconds).
    """

    # Route-specific overrides: stricter limits for sensitive endpoints
    ROUTE_LIMITS: dict[str, tuple[int, int]] = {
        "/api/v1/process":   (10, 60),   # 10 req / 60s
        "/api/v1/auth/login": (5, 60),   # 5 req / 60s  (brute-force guard)
        "/api/v1/auth":      (20, 60),
    }

    def __init__(self):
        self._redis = None
        # In-process fallback: {key: [(timestamp, ...), ...]}
        self._windows: dict[str, list[float]] = defaultdict(list)

    async def init(self) -> None:
        try:
            import redis.asyncio as aioredis
            self._redis = await aioredis.from_url(
                settings.REDIS_URL, encoding="utf-8", decode_responses=True
            )
            await self._redis.ping()
            logger.info("Rate limiter connected to Redis")
        except Exception as exc:
            logger.warning("Redis unavailable (%s) — using in-process rate limiter", exc)
            self._redis = None

    def _route_config(self, path: str) -> Tuple[int, int]:
        for prefix, (limit, window) in self.ROUTE_LIMITS.items():
            if path.startswith(prefix):
                return limit, window
        return settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW

    async def check(self, client_ip: str, path: str) -> Tuple[bool, int]:
        limit, window = self._route_config(path)
        key = f"rl:{client_ip}:{path.split('/')[3] if len(path.split('/')) > 3 else 'api'}"

        if self._redis:
            return await self._redis_check(key, limit, window)
        return self._memory_check(key, limit, window)

    async def _redis_check(self, key: str, limit: int, window: int) -> Tuple[bool, int]:
        now = time.time()
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window)
        results = await pipe.execute()
        count = results[1]
        if count >= limit:
            return False, window
        return True, 0

    def _memory_check(self, key: str, limit: int, window: int) -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - window
        # prune old entries
        self._windows[key] = [t for t in self._windows[key] if t > cutoff]
        if len(self._windows[key]) >= limit:
            oldest = self._windows[key][0]
            return False, int(window - (now - oldest)) + 1
        self._windows[key].append(now)
        return True, 0
