from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult


class OpenRedirectValidator:
    SIGNALS = {
        "param_patterns": [
            "next",
            "redirect",
            "return",
            "url",
            "goto",
            "dest",
            "destination",
            "redir",
            "target",
            "continue",
            "forward",
        ]
    }
    validator_id = "open_redirect_validator"
    priority = 88

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        patterns = [str(x).lower() for x in (state.get("param_patterns") or [])]
        return any(p in patterns for p in self.SIGNALS["param_patterns"]) and bool(state.get("endpoints"))

    def _replace_query_param(self, url: str, key: str, value: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        out = []
        replaced = False
        for k, v in pairs:
            if k == key and not replaced:
                out.append((k, value))
                replaced = True
            elif k != key:
                out.append((k, v))
        if not replaced:
            out.append((key, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out, doseq=True), parts.fragment))

    def run(self, state: Dict[str, Any]):
        payloads = [
            "https://evil.com",
            "//evil.com",
            "https%3A%2F%2Fevil.com",
            "https%253A%252F%252Fevil.com",
            "https://evil.com%0d%0aSet-Cookie:session=hijacked",
        ]

        endpoints = [ep for ep in (state.get("endpoints") or []) if isinstance(ep, str) and "?" in ep]
        params = [str(x) for x in (state.get("param_patterns") or [])]
        timeout = int(state.get("timeout", 8) or 8)
        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()

        for endpoint in endpoints:
            parsed = urlsplit(endpoint)
            query_keys = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            candidate_keys = [k for k in query_keys if k in params or k.lower() in self.SIGNALS["param_patterns"]]
            for key in candidate_keys:
                for payload in payloads:
                    probe_url = self._replace_query_param(endpoint, key, payload)
                    try:
                        response = requests.get(probe_url, headers=headers, timeout=timeout, allow_redirects=False)
                    except Exception:
                        continue

                    location = response.headers.get("Location", "")
                    body = response.text or ""
                    redirected = "evil.com" in location.lower() or "evil.com" in body.lower()
                    if redirected:
                        store.add_confirmed_vulnerability(
                            vuln_id="open_redirect_confirmed",
                            vuln_type="open_redirect_confirmed",
                            target=endpoint,
                            source_validator_id=self.validator_id,
                            metadata={"param": key, "payload": payload, "location": location},
                        )
                        return ValidationResult(
                            success=True,
                            confidence=0.96,
                            severity="high",
                            vulnerability="open-redirect",
                            evidence=Evidence(
                                request={"url": probe_url, "param": key, "payload": payload},
                                response={"status": response.status_code, "location": location, "snippet": body[:200]},
                                matched="evil.com",
                            ),
                            impact="Attacker-controlled redirects can be used for phishing, token leakage, and XSS/CSRF chaining.",
                            remediation="Use strict allowlists for redirect destinations and validate/normalize redirect targets server-side.",
                        )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="open-redirect",
            evidence=Evidence(request={"tested_endpoints": len(endpoints)}, response={}, matched=""),
        )
