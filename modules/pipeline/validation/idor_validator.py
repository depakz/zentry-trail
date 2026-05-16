"""IDOR (Insecure Direct Object Reference) validator — conservative.

This validator performs non-invasive checks by requesting several common
ID values and comparing responses. It does NOT attempt authentication,
exfiltration, or any destructive actions. Findings are returned as
"Potential IDOR — manual verification recommended" and should be
verified by a human.
"""
from __future__ import annotations

import hashlib
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = ["1", "2", "3", "9999"]
SENSITIVE_KEYWORDS = ("email", "username", "account", "profile", "first name", "last name", "id:")


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=20) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body
    except Exception:
        return 999.0, 0, ""


def _fingerprint(body: str) -> str:
    return hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest()


@register("idor")
async def validate_idor(url: str, param: str, timeout: int = 20) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    _engine = AdaptiveExploitEngine()

    # baseline (use test or first payload)
    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async with aiohttp.ClientSession() as session:
        baseline_time, _, baseline_body = await _fetch(session, baseline_url)
        baseline_fp = _fingerprint(baseline_body)

        saw_difference = False
        saw_sensitive = False

        payloads = suggest_payloads("idor", n=10) or PAYLOADS
        for payload in payloads:
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            response_time, status_code, body = await _fetch(session, test_url)
            waf = "blocked" if "blocked" in body.lower() else "unknown"

            fp = _fingerprint(body)
            different = fp != baseline_fp

            # Heuristic: presence of sensitive keywords increases confidence
            lowered = body.lower()
            sensitive = any(k in lowered for k in SENSITIVE_KEYWORDS)

            if different:
                saw_difference = True

            if sensitive:
                saw_sensitive = True

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

            _engine.record_result(payload, "idor", reward=reward, waf=waf, tech=[])

        if saw_sensitive:
            # Stronger signal but still requires manual review
            return {
                "validated": True,
                "type": "Potential IDOR — manual verification recommended",
                "url": url,
                "param": param,
                "payloads_tested": payloads,
                "evidence": "Response differences with sensitive-like content",
            }

        if saw_difference:
            return {
                "validated": True,
                "type": "Potential IDOR — manual verification recommended",
                "url": url,
                "param": param,
                "payloads_tested": payloads,
                "evidence": "Responses differ across ID values",
            }

    return None
