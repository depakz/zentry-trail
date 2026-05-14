from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Optional, Tuple

import requests

from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult

try:
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None  # type: ignore


_PROVIDER_PATTERNS = [
    "github.io",
    "heroku.com",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "shopify.com",
    "fastly.net",
    "pantheon.io",
    "surge.sh",
    "netlify.app",
    "ghost.io",
    "readme.io",
]

_SIGNATURES = [
    "there isn't a github pages site here",
    "no such app",
    "no such bucket",
    "404 not found",
    "project not found",
    "this shop is unavailable",
]


class SubdomainTakeoverValidator:
    SIGNALS = {}
    validator_id = "subdomain_takeover_validator"
    priority = 70

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        return bool(state.get("subdomains"))

    def _resolve_cname(self, subdomain: str) -> Optional[str]:
        if dns is None:
            return None
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")
            for ans in answers:
                cname = str(ans.target).rstrip(".")
                if cname:
                    return cname
        except Exception:
            return None
        return None

    def _provider_match(self, cname: str) -> Optional[str]:
        cl = cname.lower()
        for provider in _PROVIDER_PATTERNS:
            if provider in cl:
                return provider
        return None

    def _probe_target(self, cname: str, timeout: int) -> Tuple[bool, str]:
        url = f"http://{cname}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
        except Exception as exc:
            return False, str(exc)

        body = (resp.text or "").lower()
        if resp.status_code == 404 and any(sig in body for sig in _SIGNATURES):
            return True, body[:300]
        return False, body[:300]

    def _confirm_with_nuclei(self, subdomain: str) -> bool:
        try:
            proc = subprocess.run(
                ["nuclei", "-u", subdomain, "-tags", "takeover", "-silent"],
                capture_output=True,
                text=True,
                timeout=45,
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            return "takeover" in output.lower()
        except Exception:
            return False

    def run(self, state: Dict[str, Any]):
        subdomains = [s for s in (state.get("subdomains") or []) if isinstance(s, str)]
        timeout = int(state.get("timeout", 8) or 8)
        store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()

        for subdomain in subdomains:
            cname = self._resolve_cname(subdomain)
            if not cname:
                continue

            provider = self._provider_match(cname)
            if not provider:
                continue

            possible, snippet = self._probe_target(cname, timeout)
            if not possible:
                continue

            nuclei_confirmed = self._confirm_with_nuclei(subdomain)
            store.add_confirmed_vulnerability(
                vuln_id="subdomain_takeover_possible",
                vuln_type="subdomain_takeover_possible",
                target=subdomain,
                source_validator_id=self.validator_id,
                metadata={"provider": provider, "cname": cname, "nuclei_confirmed": nuclei_confirmed},
            )
            return ValidationResult(
                success=True,
                confidence=0.93 if nuclei_confirmed else 0.84,
                severity="high",
                vulnerability="subdomain-takeover-possible",
                evidence=Evidence(
                    request={"subdomain": subdomain, "cname": cname},
                    response={"provider": provider, "snippet": snippet, "nuclei_confirmed": nuclei_confirmed},
                    matched=provider,
                ),
                impact="Dangling CNAME appears claimable on a third-party provider, enabling hostile takeover of subdomain traffic.",
                remediation="Remove dangling DNS records or claim and secure the external service resource immediately.",
            )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="subdomain-takeover-possible",
            evidence=Evidence(request={"tested": len(subdomains)}, response={}, matched=""),
        )
