"""SSTI (Server-Side Template Injection) validator with reward feedback.

Uses a conservative set of payloads that evaluate simple expressions. A
finding is confirmed when the evaluated result appears in the response body
(e.g. ``{{7*7}}`` → ``49``). Partial signals (error messages, reflection)
are scored via ``compute_reward`` and recorded to the adaptive engine.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
]

ERROR_KEYWORDS = ("template", "jinja", "velocity", "twig", "undefined", "error")


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body
    except Exception:
        return 999.0, 0, ""


@register("ssti")
async def validate_ssti(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession() as session:
        baseline_time, _, baseline_body = await _fetch(session, baseline_url)

        payloads = suggest_payloads("ssti", n=12) or PAYLOADS
        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            response_time, status_code, body = await _fetch(session, test_url)
            waf = "blocked" if "blocked" in body.lower() or "ray id" in body.lower() else "unknown"

            # Confirm by finding the evaluated result (49) in response
            if "49" in body:
                _engine.record_result(payload, "ssti", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "SSTI",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Evaluated expression reflected in response",
                }

            # Look for error-based signals or template engine traces
            lowered = body.lower()
            error_signal = any(k in lowered for k in ERROR_KEYWORDS)

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

            # Boost small reward if we saw an error/template keyword
            if error_signal:
                reward = max(reward, 0.2)

            _engine.record_result(payload, "ssti", reward=reward, waf=waf, tech=[])

    return None
