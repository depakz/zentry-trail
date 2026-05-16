"""CRLF injection validator.

Attempts harmless CRLF-style payloads and looks for header injection or
reflection of injected markers. Records partial rewards via the adaptive
engine; a confirmed finding is returned only when the injected marker
appears in response headers or body.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "%0d%0aX-CRLF:%20injected",  # URL-encoded CRLF
    "%0d%0aSet-Cookie:%20crlf=1",
    "%0d%0aX-Test-CRLF:1",
]


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str, dict]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body, dict(r.headers)
    except Exception:
        return 999.0, 0, "", {}


@register("crlf_injection")
async def validate_crlf_injection(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession() as session:
        baseline_time, _, baseline_body, baseline_headers = await _fetch(session, baseline_url)

        payloads = suggest_payloads("crlf_injection", n=10) or PAYLOADS
        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            response_time, status_code, body, headers = await _fetch(session, test_url)
            waf = "blocked" if "blocked" in body.lower() else "unknown"

            # Check headers for our marker
            headers_joined = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
            if "x-crlf" in headers_joined or "x-test-crlf" in headers_joined or "crlf=1" in headers_joined:
                _engine.record_result(payload, "crlf_injection", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "CRLF Injection",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Injected header reflected in response headers",
                }

            # Check body reflection
            if "x-crlf" in body.lower() or "x-test-crlf" in body.lower() or "crlf=1" in body.lower():
                _engine.record_result(payload, "crlf_injection", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "CRLF Injection",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Injected marker reflected in response body",
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
            _engine.record_result(payload, "crlf_injection", reward=reward, waf=waf, tech=[])

    return None
