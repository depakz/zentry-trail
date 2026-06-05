import asyncio
import json
from typing import List
import httpx
from aiokafka import AIOKafkaProducer
from avvp.libs.event_schemas.schemas import ReconRawEvent, ReconNormalizedEvent
from avvp.services.osint.rate_limiter import TokenBucketRateLimiter
from .js_parser import extract_js_endpoints
from .param_finder import param_names


class CrawlerWorker:
    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.rate_limiter = TokenBucketRateLimiter(rate=20)
        self.producer = AIOKafkaProducer(bootstrap_servers=bootstrap_servers)
        self.http = httpx.AsyncClient(timeout=30)

    async def start(self):
        await self.producer.start()

    async def stop(self):
        await self.producer.stop()
        await self.http.aclose()

    async def process(self, raw_event: ReconRawEvent):
        asset = raw_event.payload.get("asset")
        if not asset:
            return
        # rate limit per request
        await self.rate_limiter.acquire(1)
        try:
            r = await self.http.get(asset)
        except Exception:
            return
        # extract endpoints from body (JS)
        body = r.text or ""
        js_endpoints = extract_js_endpoints(body)
        params = param_names(asset)

        findings = []
        # publish the main normalized event for the asset
        normalized = ReconNormalizedEvent(scan_id=raw_event.scan_id,
                                         payload={
                                             "url": asset,
                                             "status_code": r.status_code,
                                             "params": params,
                                             "js_endpoints": js_endpoints,
                                         })
        await self.producer.send_and_wait(normalized.topic, json.dumps(normalized.to_dict()).encode())

        # also publish each discovered JS endpoint as normalized events
        for ep in js_endpoints:
            await self.rate_limiter.acquire(0.5)
            n = ReconNormalizedEvent(scan_id=raw_event.scan_id, payload={"url": ep, "discovered_from": asset})
            await self.producer.send_and_wait(n.topic, json.dumps(n.to_dict()).encode())


async def run_example():
    worker = CrawlerWorker()
    await worker.start()
    try:
        ev = ReconRawEvent(scan_id="s1", payload={"asset": "https://example.com"})
        await worker.process(ev)
    finally:
        await worker.stop()

if __name__ == "__main__":
    asyncio.run(run_example())
