import json
import hashlib
import redis.asyncio as aioredis
from app.core.config import settings

_redis: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = await aioredis.from_url(
            settings.REDIS_URL, encoding="utf-8", decode_responses=True
        )
    return _redis

def _key(prefix: str, value: str) -> str:
    return f"cti:{prefix}:{hashlib.md5(value.encode()).hexdigest()}"

async def cache_get(prefix: str, value: str) -> dict | None:
    r = await get_redis()
    raw = await r.get(_key(prefix, value))
    return json.loads(raw) if raw else None

async def cache_set(prefix: str, value: str, data: dict, ttl: int | None = None) -> None:
    r = await get_redis()
    await r.setex(_key(prefix, value), ttl or settings.CACHE_TTL, json.dumps(data, default=str))

async def cache_delete(prefix: str, value: str) -> None:
    r = await get_redis()
    await r.delete(_key(prefix, value))

async def close_redis():
    global _redis
    if _redis:
        await _redis.aclose()
        _redis = None
