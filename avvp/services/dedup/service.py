import hashlib
from simhash import Simhash
import asyncio
from typing import Optional
import redis.asyncio as redis


class RedisDeduplicator:
    def __init__(self, redis_url: str = "redis://127.0.0.1:6379/0", threshold: int = 3, ttl: int = 86400):
        self.redis = redis.from_url(redis_url)
        self.threshold = threshold
        self.ttl = ttl

    def _fingerprint(self, text: str) -> int:
        return Simhash(text).value

    async def is_duplicate(self, scan_id: str, text: str) -> bool:
        fp = self._fingerprint(text)
        key_prefix = f"dedup:{scan_id}:"
        # Scan existing keys (not super efficient, but workable for prototype)
        async for key in self.redis.scan_iter(match=key_prefix + "*"):
            try:
                existing = int(await self.redis.get(key))
            except Exception:
                continue
            x = fp ^ existing
            if x.bit_count() <= self.threshold:
                return True
        # store fingerprint
        store_key = f"{key_prefix}{fp}"
        await self.redis.set(store_key, fp, ex=self.ttl)
        return False
