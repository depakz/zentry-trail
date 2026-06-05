import asyncio

from avvp.services.priority_queue.service import RedisPriorityQueue


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def zadd(self, key, mapping):
        z = self.store.setdefault(key, {})
        for k, v in mapping.items():
            z[k] = v

    async def zrevrange(self, key, start, stop, withscores=False):
        z = self.store.get(key, {})
        items = sorted(z.items(), key=lambda kv: kv[1], reverse=True)
        items = items[start:stop+1]
        if withscores:
            return [(k, v) for k, v in items]
        return [k for k, v in items]


def test_compute_score():
    profile = {'parameter_weight': 1.0, 'exposure': 0.5, 'historical_rate': 0.2, 'gnn_similarity': 0.0}
    score = RedisPriorityQueue.compute_score(profile)
    # expected = 1.0*0.4 + 0.5*0.25 + 0.2*0.2 + 0.0*0.15
    assert abs(score - (0.4 + 0.125 + 0.04)) < 1e-6


def test_push_pop(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr('redis.asyncio.from_url', lambda url: fake)

    pq = RedisPriorityQueue()
    asyncio.run(pq.push('scan1', 'item1', {'parameter_weight': 1.0}))
    res = asyncio.run(pq.pop_top('scan1', count=1))
    assert res[0][0] == 'item1'
