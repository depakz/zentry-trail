import asyncio
from typing import List
from avvp.libs.event_schemas.schemas import SurfaceSeedEvent, ReconRawEvent
from .subfinder_runner import SubfinderRunner
from .crtsh_runner import CRTSHRunner
from .amass_runner import AmassRunner
from .rate_limiter import TokenBucketRateLimiter
from .dedup import SimHashDeduplicator
from aiokafka import AIOKafkaProducer
import json


class OSINTWorker:
    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.subfinder = SubfinderRunner()
        self.crtsh = CRTSHRunner()
        self.amass = AmassRunner()
        self.rate_limiter = TokenBucketRateLimiter(rate=10)
        self.dedup = SimHashDeduplicator()
        self.producer = AIOKafkaProducer(bootstrap_servers=bootstrap_servers)

    async def start(self):
        await self.producer.start()

    async def stop(self):
        await self.producer.stop()

    async def process(self, seed_event: SurfaceSeedEvent):
        domain = seed_event.payload.get("domain") or seed_event.payload.get("target")
        if not domain:
            return
        tasks = [self.subfinder.run(domain), self.crtsh.run(domain), self.amass.run(domain)]
        results = await asyncio.gather(*tasks)
        flat = set()
        for r in results:
            for item in r:
                flat.add(item)
        for asset in sorted(flat):
            # rate limit per asset
            await self.rate_limiter.acquire(1)
            if self.dedup.is_duplicate(asset):
                continue
            event = ReconRawEvent(scan_id=seed_event.scan_id, payload={"asset": asset, "source": "osint"})
            await self.producer.send_and_wait(event.topic, json.dumps(event.to_dict()).encode())


async def run_worker_example():
    worker = OSINTWorker()
    await worker.start()
    try:
        seed = SurfaceSeedEvent(scan_id="example-scan", payload={"domain": "example.com"})
        await worker.process(seed)
    finally:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(run_worker_example())
