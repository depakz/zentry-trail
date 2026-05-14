from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.pipeline.brain.fact_store import FactCategory, FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult


class CSRFValidator:
    SIGNALS = {
        "endpoint_patterns": ["/login", "/settings", "/profile", "/password", "/email", "/api"],
        "facts": ["xss_confirmed"],
    }
    validator_id = "csrf_validator"
    priority = 82

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = [str(x).lower() for x in (state.get("endpoints") or [])]
        return any(tok in ep for tok in ["login", "settings", "profile", "password", "email", "api"] for ep in endpoints)

    def run(self, state: Dict[str, Any]):
        endpoints = [ep for ep in (state.get("endpoints") or []) if isinstance(ep, str)]
        post_endpoints = [ep for ep in endpoints if any(k in ep.lower() for k in ["login", "settings", "profile", "password", "email", "api"]) ]
        timeout = int(state.get("timeout", 8) or 8)
        store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()

        for endpoint in post_endpoints:
            headers = {"User-Agent": "security-pipeline-validator/1.0"}
            try:
                get_resp = requests.get(endpoint, headers=headers, timeout=timeout, allow_redirects=True)
            except Exception:
                continue

            body_l = (get_resp.text or "").lower()
            has_token = any(tok in body_l for tok in ["csrf", "token", "nonce"]) and "hidden" in body_l

            set_cookie = get_resp.headers.get("Set-Cookie", "")
            cookie_l = set_cookie.lower()
            has_samesite = "samesite=lax" in cookie_l or "samesite=strict" in cookie_l

            probe_headers = dict(headers)
            probe_headers["Origin"] = "https://evil.example"
            probe_headers["Referer"] = "https://evil.example/poc"
            try:
                cross_resp = requests.post(endpoint, headers=probe_headers, data={"test": "1"}, timeout=timeout, allow_redirects=False)
            except Exception:
                continue

            origin_checked = cross_resp.status_code in {400, 401, 403}

            if not has_token and not has_samesite and not origin_checked:
                metadata = {
                    "endpoint": endpoint,
                    "missing_token": True,
                    "missing_samesite": True,
                    "missing_origin_validation": True,
                }
                store.add_confirmed_vulnerability(
                    vuln_id="csrf_confirmed",
                    vuln_type="csrf_confirmed",
                    target=endpoint,
                    source_validator_id=self.validator_id,
                    metadata=metadata,
                )

                has_xss_fact = False
                for fact in store.get_facts_by_category(FactCategory.CONFIRMED_VULNERABILITY):
                    if fact.key == "xss_confirmed" or "xss_confirmed" in str(fact.value):
                        has_xss_fact = True
                        break
                if has_xss_fact:
                    store.add_confirmed_vulnerability(
                        vuln_id="xss_csrf_chain_ready",
                        vuln_type="xss_csrf_chain_ready",
                        target=endpoint,
                        source_validator_id=self.validator_id,
                    )

                return ValidationResult(
                    success=True,
                    confidence=0.92,
                    severity="high",
                    vulnerability="csrf-missing-protections",
                    evidence=Evidence(
                        request={"endpoint": endpoint},
                        response={"cross_origin_status": cross_resp.status_code, "set_cookie": set_cookie[:200]},
                        matched="all_three_missing",
                    ),
                    impact="State-changing endpoint appears vulnerable to CSRF due to missing token, SameSite, and Origin/Referer checks.",
                    remediation="Add anti-CSRF token validation, SameSite cookies, and strict Origin/Referer verification.",
                )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="csrf-missing-protections",
            evidence=Evidence(request={"tested": len(post_endpoints)}, response={}, matched=""),
        )
