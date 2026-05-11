"""Template for a native async validator.

This file shows the preferred pattern for new validators:
- use one shared httpx.AsyncClient when called from orchestration code
- request a baseline first
- inject a payload and compare response headers/body/timing
- parse HTML with BeautifulSoup when structural signals matter

The existing DAG engine executes validators synchronously, so the public
`run()` method remains sync and delegates to the async implementation.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from modules.pipeline.engine.models import Evidence, ValidationResult


@dataclass
class NativeSignal:
    baseline_status: int
    probe_status: int
    baseline_length: int
    probe_length: int
    elapsed_delta_ms: float
    reflected: bool


class NativeValidatorTemplate:
    """Reference implementation for baseline / trigger / compare checks."""

    vulnerability = "native_template"

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]):
        try:
            return asyncio.run(self.run_async(state))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self.run_async(state))
            finally:
                loop.close()

    async def run_async(self, state: Dict[str, Any]):
        target = str(state.get("url") or state.get("target") or "").strip()
        if not target:
            return None

        timeout = float(state.get("timeout", 8) or 8)
        headers = {"User-Agent": "zentry-native-validator/1.0"}
        cookie = state.get("cookie")
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie.strip()

        param_name = state.get("param") or self._first_param(target) or "q"
        baseline_url = self._replace_param(target, param_name, "baseline")
        payload = state.get("payload") or "'\"<svg onload=alert(1)><!--"
        probe_url = self._replace_param(target, param_name, payload)

        timeout_cfg = httpx.Timeout(timeout, connect=min(5.0, timeout))
        async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=True, headers=headers) as client:
            baseline_start = time.perf_counter()
            baseline = await client.get(baseline_url)
            baseline_elapsed = (time.perf_counter() - baseline_start) * 1000.0

            probe_start = time.perf_counter()
            probe = await client.get(probe_url)
            probe_elapsed = (time.perf_counter() - probe_start) * 1000.0

        baseline_body = baseline.text or ""
        probe_body = probe.text or ""
        baseline_soup = BeautifulSoup(baseline_body, "html.parser")
        probe_soup = BeautifulSoup(probe_body, "html.parser")

        signal = NativeSignal(
            baseline_status=baseline.status_code,
            probe_status=probe.status_code,
            baseline_length=len(baseline_body),
            probe_length=len(probe_body),
            elapsed_delta_ms=round(probe_elapsed - baseline_elapsed, 2),
            reflected=payload in probe_body or probe_soup.get_text(" ").find(payload) >= 0,
        )

        matched = signal.reflected or abs(signal.probe_length - signal.baseline_length) > 24 or signal.elapsed_delta_ms > 750
        evidence = Evidence(
            request={
                "baseline_url": baseline_url,
                "probe_url": probe_url,
                "param": param_name,
                "payload": payload,
            },
            response={
                "baseline": {
                    "status_code": baseline.status_code,
                    "headers": dict(baseline.headers),
                    "title": baseline_soup.title.string if baseline_soup.title and baseline_soup.title.string else "",
                },
                "probe": {
                    "status_code": probe.status_code,
                    "headers": dict(probe.headers),
                    "title": probe_soup.title.string if probe_soup.title and probe_soup.title.string else "",
                },
                "signal": signal.__dict__,
            },
            matched=payload if matched else "",
            extra={
                "coverage_markers": ["native_template_signal"],
                "baseline_status": baseline.status_code,
                "probe_status": probe.status_code,
            },
        )

        return ValidationResult(
            success=matched,
            confidence=0.65 if matched else 0.2,
            confidence_score=0.65 if matched else 0.2,
            severity="medium" if matched else "info",
            vulnerability=self.vulnerability,
            evidence=evidence,
            impact="Native baseline/trigger/validate pattern demonstrated.",
            remediation="Replace the placeholder payload logic with a real validator for the target condition.",
        )

    def _first_param(self, url: str) -> Optional[str]:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for key, _ in pairs:
            if key:
                return key
        return None

    def _replace_param(self, url: str, key: str, value: str) -> str:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        updated = []
        replaced = False
        for current_key, current_value in pairs:
            if current_key == key and not replaced:
                updated.append((current_key, value))
                replaced = True
            else:
                updated.append((current_key, current_value))
        if not replaced:
            updated.append((key, value))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(updated, doseq=True), parsed.fragment))