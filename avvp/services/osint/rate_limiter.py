import asyncio
import time

class TokenBucketRateLimiter:
    def __init__(self, rate: float, capacity: float = None):
        self.rate = rate
        self.capacity = capacity if capacity is not None else rate
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            # wait until tokens available
            needed = tokens - self._tokens
            wait_time = needed / self.rate
        await asyncio.sleep(wait_time)
        return await self.acquire(tokens)
