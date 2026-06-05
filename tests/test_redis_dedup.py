import asyncio

from avvp.services.dedup.service import RedisDeduplicator


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def scan_iter(self, match=None):
        # async generator
        prefix = match[:-1] if match and match.endswith('*') else match
        for k in list(self.store.keys()):
            if prefix is None or k.startswith(prefix):
                yield k

    async def get(self, key):
        return str(self.store.get(key)) if key in self.store else None

    async def set(self, key, value, ex=None):
        self.store[key] = value
        return True


def test_redis_deduplicator():
    fake = FakeRedis()
    rd = RedisDeduplicator()
    rd.redis = fake

    # first time should be not duplicate
    res1 = asyncio.run(rd.is_duplicate('s1', 'example.com'))
    assert res1 is False

    # second time with same content should be duplicate
    res2 = asyncio.run(rd.is_duplicate('s1', 'example.com'))
    assert res2 is True
