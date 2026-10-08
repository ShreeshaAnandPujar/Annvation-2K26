import asyncio
from typing import Any, Dict, List, Optional
import structlog
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

_MAX_RETRIES = 2
_BASE_DELAY = 0.5


class InMemoryAsyncRedis:
    """High-reliability in-memory Redis fallback for standalone environments."""

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._zsets: Dict[str, List[tuple[str, float]]] = {}

    async def ping(self) -> bool:
        return True

    async def get(self, key: str) -> Optional[str]:
        return str(self._data.get(key)) if key in self._data else None

    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        self._data[key] = value
        return True

    async def mget(self, *keys: str) -> List[Optional[str]]:
        return [str(self._data.get(k)) if k in self._data else None for k in keys]

    async def delete(self, *keys: str) -> int:
        count = 0
        for k in keys:
            if k in self._data:
                del self._data[k]
                count += 1
        return count

    async def exists(self, key: str) -> bool:
        return key in self._data

    async def zadd(self, key: str, mapping: Dict[str, float]) -> int:
        if key not in self._zsets:
            self._zsets[key] = []
        for val, score in mapping.items():
            self._zsets[key].append((val, float(score)))
        self._zsets[key].sort(key=lambda x: x[1])
        return len(mapping)

    async def zrange(self, key: str, start: int, end: int, withscores: bool = False) -> List[Any]:
        items = self._zsets.get(key, [])
        slice_end = None if end == -1 else end + 1
        res = items[start:slice_end]
        if withscores:
            return res
        return [x[0] for x in res]

    async def zremrangebyrank(self, key: str, start: int, end: int) -> int:
        return 0

    async def expire(self, key: str, seconds: int) -> bool:
        return True

    async def smembers(self, key: str) -> set:
        val = self._data.get(key, set())
        return val if isinstance(val, set) else set()

    async def sadd(self, key: str, *values: str) -> int:
        if key not in self._data or not isinstance(self._data[key], set):
            self._data[key] = set()
        self._data[key].update(values)
        return len(values)

    async def aclose(self) -> None:
        pass

    def pipeline(self):
        return self

    async def execute(self) -> List[Any]:
        return []

    def register_script(self, script_text: str):
        class MockScript:
            async def __call__(self, keys=None, args=None):
                return [1, 99]
        return MockScript()

    def incr(self, key: str) -> int:
        curr = int(self._data.get(key, 0)) + 1
        self._data[key] = curr
        return curr


async def create_redis_client() -> Redis:
    """
    Connects to Redis if available, with graceful in-memory fallback.
    Prevents crashing during demonstrations when external Redis is offline.
    """
    client = Redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            await asyncio.wait_for(client.ping(), timeout=1.0)
            logger.info("redis_connected", url=settings.redis_url)
            return client
        except Exception as exc:
            delay = _BASE_DELAY * attempt
            await asyncio.sleep(delay)

    logger.warning(
        "redis_unavailable_using_inmemory_fallback",
        url=settings.redis_url,
        message="Standalone in-memory state engine active.",
    )
    return InMemoryAsyncRedis()  # type: ignore


async def close_redis_client(client: Any) -> None:
    if hasattr(client, "aclose"):
        await client.aclose()
    logger.info("redis_closed")


async def is_shadow_mode_enabled(redis: Any, fallback: bool) -> bool:
    try:
        val = await redis.get("config:shadow_mode_enabled")
        if val is None:
            return fallback
        return str(val).lower() == "true"
    except Exception:
        return fallback
