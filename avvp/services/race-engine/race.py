import asyncio
import httpx
from typing import List, Dict

async def run_race_requests(url: str, concurrency: int = 20, payloads: List[Dict] = None) -> Dict:
    payloads = payloads or [{} for _ in range(concurrency)]
    async with httpx.AsyncClient(timeout=15) as client:
        tasks = []
        for i in range(concurrency):
            tasks.append(client.post(url, json=payloads[i]))
        responses = await asyncio.gather(*tasks, return_exceptions=True)
    statuses = [getattr(r, 'status_code', None) for r in responses]
    bodies = [getattr(r, 'text', '') for r in responses]
    # simplistic anomaly detection: differing status codes or duplicated resource ids
    return {'statuses': statuses, 'body_samples': bodies[:5]}
