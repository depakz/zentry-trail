from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult


class StoredXSSValidator:
    SIGNALS = {
        "endpoint_patterns": ["/comment", "/post", "/review", "/message", "/profile", "/bio", "/name", "/title"]
    }
    validator_id = "stored_xss_validator"
    priority = 78

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = [str(x).lower() for x in (state.get("endpoints") or [])]
        return any(k in ep for ep in endpoints for k in ["comment", "post", "review", "message", "profile", "bio", "name", "title"])

    def _playwright_exec_confirm(self, url: str, timeout_ms: int, browser: Any = None) -> bool:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            return False

        payload_seen = False
        try:
            if browser is not None:
                page = browser.new_page()
                _close_browser = False
            else:
                with sync_playwright() as p:
                    _browser = p.chromium.launch(headless=True)
                    page = _browser.new_page()
                    _close_browser = True

                    def on_dialog(dialog):
                        nonlocal payload_seen
                        payload_seen = True
                        try:
                            dialog.accept()
                        except Exception:
                            pass

                    page.on("dialog", on_dialog)
                    page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                    page.wait_for_timeout(1200)
                    page.close()
                    if _close_browser:
                        _browser.close()
                return payload_seen

                def on_dialog(dialog):
                    nonlocal payload_seen
                    payload_seen = True
                    try:
                        dialog.accept()
                    except Exception:
                        pass

                page.on("dialog", on_dialog)
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(1200)
                page.close()
        except Exception:
            return False

        return payload_seen

    def run(self, state: Dict[str, Any]):
        endpoints = [ep for ep in (state.get("endpoints") or []) if isinstance(ep, str)]
        submit_targets = [ep for ep in endpoints if any(k in ep.lower() for k in ["comment", "post", "review", "message", "profile"])]
        render_targets = [ep for ep in endpoints if any(k in ep.lower() for k in ["profile", "post", "comment", "review", "message", "bio", "title", "name"])]
        if not submit_targets or not render_targets:
            return None

        payload = state.get("stored_xss_payload") or "<script>alert('zentry')</script>"
        timeout = int(state.get("timeout", 8) or 8)
        store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()

        for submit in submit_targets[:5]:
            try:
                requests.post(
                    submit,
                    data={"comment": payload, "message": payload, "bio": payload, "title": payload, "name": payload},
                    headers={"User-Agent": "security-pipeline-validator/1.0"},
                    timeout=timeout,
                    allow_redirects=True,
                )
            except Exception:
                continue

            for render in render_targets[:8]:
                try:
                    resp = requests.get(render, headers={"User-Agent": "security-pipeline-validator/1.0"}, timeout=timeout, allow_redirects=True)
                except Exception:
                    continue

                body = resp.text or ""
                unescaped = payload in body
                if not unescaped:
                    continue

                js_exec = self._playwright_exec_confirm(
                    render,
                    timeout_ms=max(8000, timeout * 1000),
                    browser=state.get("browser"),
                )
                if js_exec or unescaped:
                    store.add_confirmed_vulnerability(
                        vuln_id="stored_xss_confirmed",
                        vuln_type="stored_xss_confirmed",
                        target=render,
                        source_validator_id=self.validator_id,
                        metadata={"submit": submit, "render": render, "js_exec": js_exec},
                    )
                    return ValidationResult(
                        success=True,
                        confidence=0.95 if js_exec else 0.86,
                        severity="high",
                        vulnerability="stored-xss",
                        evidence=Evidence(
                            request={"submit_endpoint": submit, "render_endpoint": render},
                            response={"status": resp.status_code, "snippet": body[:250], "js_exec": js_exec},
                            matched=payload,
                        ),
                        impact="Payload persisted and rendered in a later view, enabling stored cross-site scripting.",
                        remediation="Apply strict contextual output encoding, input validation, and CSP with nonce-based script controls.",
                    )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="stored-xss",
            evidence=Evidence(request={"tested_submit": len(submit_targets)}, response={}, matched=""),
        )
