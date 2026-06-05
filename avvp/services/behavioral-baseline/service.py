import redis.asyncio as redis
import json
from typing import Dict, Any

class BehavioralBaseline:
    def __init__(self, redis_url: str = "redis://127.0.0.1:6379/0"):
        self.redis = redis.from_url(redis_url)

    async def record_baseline(self, scan_id: str, endpoint_hash: str, metrics: Dict[str, Any]):
        key = f"bsm:{scan_id}:{endpoint_hash}"
        await self.redis.set(key, json.dumps(metrics))

    async def get_baseline(self, scan_id: str, endpoint_hash: str):
        key = f"bsm:{scan_id}:{endpoint_hash}"
        val = await self.redis.get(key)
        if not val:
            return None
        return json.loads(val)
