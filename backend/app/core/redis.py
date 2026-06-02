from __future__ import annotations

from typing import Any

import structlog
from redis.asyncio import Redis, ConnectionPool
from redis.asyncio.client import Pipeline

from app.core.config import settings

logger = structlog.get_logger(__name__)


class RedisManager:
    """Manages the Redis connection pool lifecycle."""

    _pool: ConnectionPool | None = None
    _client: Redis | None = None  # type: ignore[type-arg]

    async def initialize(self) -> None:
        self._pool = ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
        )
        self._client = Redis(connection_pool=self._pool)
        await self._verify_connection()
        logger.info("redis_initialized", url=self._masked_url())

    async def _verify_connection(self) -> None:
        assert self._client is not None
        await self._client.ping()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._pool is not None:
            await self._pool.aclose()
            self._pool = None
        logger.info("redis_connection_closed")

    def get_client(self) -> "Redis[str]":
        if self._client is None:
            raise RuntimeError("Redis not initialized. Call initialize() first.")
        return self._client

    async def check_health(self) -> bool:
        try:
            assert self._client is not None
            await self._client.ping()
            return True
        except Exception:
            return False

    def _masked_url(self) -> str:
        url = settings.REDIS_URL
        if "@" in url:
            at_idx = url.index("@")
            return "redis://***:***" + url[at_idx:]
        return url


# ─── Singleton ────────────────────────────────────────────────────────────────
redis_manager = RedisManager()


# ─── FastAPI dependency ───────────────────────────────────────────────────────
async def get_redis() -> "Redis[str]":
    return redis_manager.get_client()


# ─── Tenant-scoped Redis client ───────────────────────────────────────────────

class TenantRedisClient:
    """
    Wraps the Redis client and automatically prefixes all keys with
    `tenant:{tenant_id}:{subsystem}:`. This enforces tenant isolation
    at the infrastructure level — callers never construct keys manually.

    Usage:
        client = TenantRedisClient(redis, tenant_id="abc", subsystem="detect")
        await client.set("threshold:rule_123:host_01", 5, ex=60)
        # Actual key: tenant:abc:detect:threshold:rule_123:host_01
    """

    def __init__(
        self,
        redis: "Redis[str]",
        tenant_id: str,
        subsystem: str,
    ) -> None:
        self._redis = redis
        self._tenant_id = tenant_id
        self._subsystem = subsystem
        self._prefix = f"tenant:{tenant_id}:{subsystem}:"

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    # ─── Core operations ──────────────────────────────────────────────────────

    async def get(self, key: str) -> str | None:
        return await self._redis.get(self._key(key))

    async def set(
        self,
        key: str,
        value: Any,
        ex: int | None = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool | None:
        return await self._redis.set(self._key(key), value, ex=ex, nx=nx, xx=xx)

    async def delete(self, *keys: str) -> int:
        return await self._redis.delete(*[self._key(k) for k in keys])

    async def exists(self, key: str) -> bool:
        return bool(await self._redis.exists(self._key(key)))

    async def expire(self, key: str, seconds: int) -> bool:
        return bool(await self._redis.expire(self._key(key), seconds))

    async def ttl(self, key: str) -> int:
        return await self._redis.ttl(self._key(key))

    async def incr(self, key: str) -> int:
        return await self._redis.incr(self._key(key))

    async def incrby(self, key: str, amount: int) -> int:
        return await self._redis.incrby(self._key(key), amount)

    async def hget(self, name: str, field: str) -> str | None:
        return await self._redis.hget(self._key(name), field)

    async def hset(self, name: str, mapping: dict[str, Any]) -> int:
        return await self._redis.hset(self._key(name), mapping=mapping)

    async def hgetall(self, name: str) -> dict[str, str]:
        return await self._redis.hgetall(self._key(name))

    async def hdel(self, name: str, *fields: str) -> int:
        return await self._redis.hdel(self._key(name), *fields)

    async def publish(self, channel_suffix: str, message: str) -> int:
        channel = f"tenant:{self._tenant_id}:{channel_suffix}"
        return await self._redis.publish(channel, message)

    # ─── Redis Streams ────────────────────────────────────────────────────────

    async def xadd(
        self,
        stream: str,
        fields: dict[str, Any],
        maxlen: int | None = None,
        approximate: bool = True,
    ) -> str:
        kwargs: dict[str, Any] = {}
        if maxlen is not None:
            kwargs["maxlen"] = maxlen
            kwargs["approximate"] = approximate
        return await self._redis.xadd(self._key(stream), fields, **kwargs)

    async def xreadgroup(
        self,
        group: str,
        consumer: str,
        streams: dict[str, str],
        count: int | None = None,
        block: int | None = None,
    ) -> list[Any]:
        prefixed = {self._key(k): v for k, v in streams.items()}
        return await self._redis.xreadgroup(group, consumer, prefixed, count=count, block=block)

    async def xack(self, stream: str, group: str, *message_ids: str) -> int:
        return await self._redis.xack(self._key(stream), group, *message_ids)

    async def xgroup_create(
        self,
        stream: str,
        group: str,
        id: str = "0",
        mkstream: bool = True,
    ) -> bool:
        try:
            await self._redis.xgroup_create(self._key(stream), group, id, mkstream=mkstream)
            return True
        except Exception as e:
            if "BUSYGROUP" in str(e):
                return False  # group already exists
            raise

    async def xautoclaim(
        self,
        stream: str,
        group: str,
        consumer: str,
        min_idle_time: int,
        start_id: str = "0-0",
        count: int | None = None,
    ) -> tuple[str, list[Any]]:
        return await self._redis.xautoclaim(
            self._key(stream), group, consumer, min_idle_time, start_id, count=count
        )

    # ─── Rate limiting ────────────────────────────────────────────────────────

    async def check_rate_limit(self, resource: str, limit: int, window_secs: int) -> tuple[bool, int]:
        """
        Sliding window rate limit counter.
        Returns (is_allowed, remaining).
        """
        key = self._key(f"rate:{resource}")
        current = await self._redis.incr(key)
        if current == 1:
            await self._redis.expire(key, window_secs)
        remaining = max(0, limit - current)
        return current <= limit, remaining

    # ─── Sorted sets (used by correlation temporal windows) ───────────────────

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        return await self._redis.zadd(self._key(key), mapping)  # type: ignore[return-value]

    async def zrangebyscore(
        self,
        key: str,
        min: float | str,
        max: float | str,
    ) -> list[str]:
        return await self._redis.zrangebyscore(self._key(key), min, max)  # type: ignore[return-value]

    async def zremrangebyscore(
        self,
        key: str,
        min: float | str,
        max: float | str,
    ) -> int:
        return await self._redis.zremrangebyscore(self._key(key), min, max)  # type: ignore[return-value]

    async def zremrangebyrank(self, key: str, start: int, stop: int) -> int:
        return await self._redis.zremrangebyrank(self._key(key), start, stop)  # type: ignore[return-value]

    async def zcount(self, key: str, min: float | str, max: float | str) -> int:
        return await self._redis.zcount(self._key(key), min, max)  # type: ignore[return-value]

    async def zrange(self, key: str, start: int, stop: int) -> list[str]:
        return await self._redis.zrange(self._key(key), start, stop)  # type: ignore[return-value]

    # ─── Redis Sets ───────────────────────────────────────────────────────────

    async def sadd(self, key: str, *values: str) -> int:
        return await self._redis.sadd(self._key(key), *values)

    async def srem(self, key: str, *values: str) -> int:
        return await self._redis.srem(self._key(key), *values)

    async def smembers(self, key: str) -> set[str]:
        return await self._redis.smembers(self._key(key))  # type: ignore[return-value]

    async def scard(self, key: str) -> int:
        return await self._redis.scard(self._key(key))

    async def sismember(self, key: str, value: str) -> bool:
        return bool(await self._redis.sismember(self._key(key), value))

    # ─── Pipeline ─────────────────────────────────────────────────────────────

    def pipeline(self) -> Pipeline:  # type: ignore[type-arg]
        return self._redis.pipeline()
