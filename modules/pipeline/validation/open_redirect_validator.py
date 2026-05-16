"""Open Redirect validator.

Detects open redirect behavior by supplying an external URL and checking if
the response contains a redirect to the supplied target or reflects it.
This validator avoids following redirects; it only inspects response headers
and response bodies for evidence and records rewards.
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "https://example.com",
    "//example.com",
    "https://attacker.example.com",
]


@register("open_redirect")
async def validate_open_redirect(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession(allow_redirects=False) as session:
        # baseline
        try:
            async with session.get(baseline_url, timeout=timeout) as r:
                baseline_body = await r.text(errors="ignore")
                baseline_status = r.status
        except Exception:
            baseline_body = ""
            baseline_status = 0

        payloads = suggest_payloads("open_redirect", n=10) or PAYLOADS
        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                async with session.get(test_url, timeout=timeout) as r:
                    body = await r.text(errors="ignore")
                    status = r.status
                    loc = r.headers.get("Location", "")
            except Exception:
                body = ""
                status = 0
                loc = ""

            waf = "blocked" if "blocked" in body.lower() else "unknown"

            # Confirm by Location header pointing to our payload host
            if payload in loc or payload in body:
                _engine.record_result(payload, "open_redirect", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "Open Redirect",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Location: {loc}",
                }

            reward = 0.0 if waf == "blocked" else compute_reward(
                validated=False,
                response_time=0.0,
                baseline_time=0.0,
                response_body=body,
                baseline_body=baseline_body,
                status_code=status,
                waf_blocked=False,
                payload=payload,
            )
            _engine.record_result(payload, "open_redirect", reward=reward, waf=waf, tech=[])

    return None
