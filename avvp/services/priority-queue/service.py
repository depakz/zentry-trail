import redis.asyncio as redis
from typing import Dict, Any, List, Tuple

class RedisPriorityQueue:
    def __init__(self, redis_url: str = "redis://127.0.0.1:6379/0"):
        self.redis = redis.from_url(redis_url)

    @staticmethod
    def compute_score(profile: Dict[str, Any]) -> float:
        # profile keys: parameter_weight (0..1), exposure (0..1), historical_rate (0..1), gnn_similarity (0..1)
        w = {
            'parameter_weight': 0.4,
            'exposure': 0.25,
            'historical_rate': 0.2,
            'gnn_similarity': 0.15,
        }
        score = 0.0
        for k, weight in w.items():
            score += profile.get(k, 0.0) * weight
        return float(score)

    async def push(self, scan_id: str, item_id: str, profile: Dict[str, Any]):
        key = f"pq:{scan_id}:endpoints"
        score = self.compute_score(profile)
        await self.redis.zadd(key, {item_id: score})

    async def pop_top(self, scan_id: str, count: int = 1) -> List[Tuple[str, float]]:
        key = f"pq:{scan_id}:endpoints"
        res = await self.redis.zrevrange(key, 0, count - 1, withscores=True)
        return [(r.decode() if isinstance(r, bytes) else r, s) for r, s in res]
