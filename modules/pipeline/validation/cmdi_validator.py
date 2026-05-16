"""Command Injection (CMDI) validator — time-based only (safe).

This validator uses only time-delay payloads (e.g. `; sleep 5`) to detect
blind command injection without attempting any data exfiltration. It records
partial rewards via the adaptive engine for weaker signals.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "; sleep 5",
    " && sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
]

THRESHOLD = 4.5


async def _timed(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body
    except Exception:
        return 999.0, 0, ""


@register("cmdi")
async def validate_cmdi(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession() as session:
        baseline_time, _, baseline_body = await _timed(session, baseline_url)

        suggested = suggest_payloads("cmdi", n=12)
        # Only include suggested payloads that look like time-delay probes
        suggested_timed = [p for p in (suggested or []) if isinstance(p, str) and "sleep" in p]
        for payload in PAYLOADS + suggested_timed:
            qs[param] = ["test" + payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            t, status, body = await _timed(session, test_url)
            waf = "blocked" if "blocked" in body.lower() or "ray id" in body.lower() else "unknown"

            reward = 0.0 if waf == "blocked" else compute_reward(
                validated=False,
                response_time=t,
                baseline_time=baseline_time,
                response_body=body,
                baseline_body=baseline_body,
                status_code=status,
                waf_blocked=False,
                payload=payload,
            )

            # If delay is large, re-test to reduce flukes
            if t - baseline_time >= THRESHOLD:
                t2, status2, body2 = await _timed(session, test_url)
                if t2 - baseline_time >= THRESHOLD:
                    _engine.record_result(payload, "cmdi", reward=1.0, waf=waf, tech=[])
                    return {
                        "validated": True,
                        "type": "Command Injection (time-based)",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Baseline={baseline_time:.2f}s, Injected={t2:.2f}s",
                    }
                reward = compute_reward(
                    validated=False,
                    response_time=t2,
                    baseline_time=baseline_time,
                    response_body=body2,
                    baseline_body=baseline_body,
                    status_code=status2,
                    waf_blocked=False,
                    payload=payload,
                )

            _engine.record_result(payload, "cmdi", reward=reward, waf=waf, tech=[])

    return None
