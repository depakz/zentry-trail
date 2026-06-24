"""
zentry/validators/base.py

Base class for all validators. Supports two constructor patterns:
1. Simple: BaseValidator(session, evidence_store)  — for sqli.py, xss.py etc.
2. Discovery: BaseValidator(context=None, auth_manager=None) — for discovered validators
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from zentry.session import Evidence, ValidationResult, EvidenceBundle
from zentry.evidence.store import EvidenceStore, EvidenceCollector, format_request_from_prepared, format_response_from_response


class Finding:
    """
    A standardized representation of a security finding.
    """
    def __init__(self, url: str, type: str, severity: str, description: str, evidence: Optional[Dict[str, Any]] = None):
        self.url = url
        self.type = type
        self.severity = severity
        self.description = description
        self.evidence = evidence if evidence is not None else {}

    def to_dict(self):
        return {
            "url": self.url,
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
        }


class BaseValidator(ABC):
    """
    Abstract Base Class for all validators.

    Supports flexible constructor:
      - BaseValidator()  — for discovered validators
      - BaseValidator(session=s, evidence_store=e)  — for simple validators
      - BaseValidator(context=c, auth_manager=a)  — for discovery-pattern validators
    """
    def __init__(self, session=None, evidence_store=None, context=None, auth_manager=None):
        self.session = session
        self.evidence_store = evidence_store
        self.context = context
        self.auth_manager = auth_manager
        self.validator_id = getattr(self, "validator_id", self.__class__.__name__)
        self.priority = getattr(self, "priority", 0)
        self.SIGNALS = getattr(self, "SIGNALS", {})

    def validate(self, url: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """
        Optional validation method for simple validators.
        Override in subclasses if needed.
        """
        return None

    def can_run(self, state: Dict[str, Any]) -> bool:
        """Check if this validator should run for the given scan state."""
        return True

    async def run(self, state: Dict[str, Any]) -> Optional[Any]:
        """Run the validator against the given scan state. Override in subclasses."""
        return None

    def get_auth_session(self, user: str = 'default'):
        """
        Retrieves an authenticated session from the AuthManager.
        """
        if self.auth_manager and hasattr(self.auth_manager, 'get_session'):
            return self.auth_manager.get_session()
        import requests
        return requests.Session()

    def confirm_finding(self, url=None, type=None, severity=None, description=None,
                        evidence=None, request_obj=None, response_obj=None,
                        vulnerability=None, confidence=0.9, param=None,
                        payload=None, impact=None, remediation=None, **kwargs) -> Any:
        """
        Creates a confirmed finding. Supports two calling conventions:
        1. Simple: confirm_finding(url, type, severity, description, evidence)
        2. Rich: confirm_finding(request_obj, response_obj, vulnerability, severity, confidence, ...)
        """
        if request_obj is not None or vulnerability is not None:
            # Rich validation result path
            req_text = ""
            res_text = ""
            if request_obj is not None:
                req_text = format_request_from_prepared(request_obj)
            if response_obj is not None:
                res_text = format_response_from_response(response_obj)

            evidence_data = Evidence(
                request={
                    "target": url or (request_obj.url if request_obj and hasattr(request_obj, 'url') else ""),
                    "url": url or (request_obj.url if request_obj and hasattr(request_obj, 'url') else ""),
                    "payload": payload or "",
                    "param": param or "",
                    "method": (request_obj.method if request_obj and hasattr(request_obj, 'method') else "GET"),
                },
                response={
                    "snippet": res_text[:500] if res_text else "",
                    "status": (response_obj.status_code if response_obj and hasattr(response_obj, 'status_code') else None),
                },
                matched=str(payload or ""),
            )

            bundle = EvidenceBundle(
                raw_request=req_text,
                raw_response=res_text,
                matched_indicator=str(payload or ""),
                execution_proof={},
                tool_logs=[],
                metadata={}
            )

            result = ValidationResult(
                success=True,
                confidence=confidence,
                severity=severity or "medium",
                vulnerability=vulnerability or type or "unknown",
                evidence=evidence_data,
                impact=impact or "",
                remediation=remediation or "",
                evidence_bundle=bundle,
            )
            # Store validator_id on the result object for reporting
            result.validator_id = self.validator_id
            result.validator_class = self.__class__.__name__

            # Capture evidence files if collector is available
            if self.evidence_store and hasattr(self.evidence_store, 'save_single_evidence'):
                try:
                    ev_paths = self.evidence_store.save_single_evidence(
                        index=0,
                        vuln=vulnerability or type or "unknown",
                        endpoint=url or "",
                        prepared_request=request_obj,
                        response_obj=response_obj,
                    )
                    if ev_paths:
                        result.evidence_bundle.metadata.update(ev_paths)
                except Exception:
                    pass

            return result

        # Simple finding path (original)
        bundle_path = ""
        if self.evidence_store and evidence:
            try:
                bundle_path = self.evidence_store.save_bundle(evidence) if hasattr(self.evidence_store, 'save_bundle') else ""
            except Exception:
                pass

        finding = Finding(
            url=url or "",
            type=type or "",
            severity=severity or "info",
            description=description or "",
            evidence={"bundle_path": bundle_path} if bundle_path else (evidence or {}),
        )
        if self.session and hasattr(self.session, 'add_finding'):
            self.session.add_finding(finding)
        return finding


ATTACK_VARIANT_CATALOG = {
    "A02": {
        "sensitive_headers": [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "X-API-Key",
            "X-Auth-Token",
            "X-Access-Token",
            "X-Amz-Security-Token",
        ],
        "weak_tls_versions": ["TLSv1", "TLSv1.1"],
    },
    "A03": {
        "sqli_payloads": ["1'", "1\"", "1' OR '1'='1", "1) OR (1=1--"],
        "xss_payloads": [
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ],
        "command_payloads": ["||echo SECURITY_PIPELINE_A03", ";echo SECURITY_PIPELINE_A03", "$(echo SECURITY_PIPELINE_A03)"],
        "file_payloads": ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd"],
        "template_payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        "ldap_payloads": ["*)(uid=*)", "*)(|(uid=*))", "*)(cn=*)"],
    },
    "A05": {
        "method_variants": ["OPTIONS", "TRACE"],
        "debug_markers": ["stack trace", "exception in thread", "debug=true", "directory listing"],
    },
    "A06": {
        "version_headers": ["Server", "X-Powered-By", "Via"],
        "cve_pattern_hints": ["CVE-"],
    },
    "A10": {
        "ssrf_params": ["url", "uri", "dest", "destination", "next", "redirect", "path", "callback", "endpoint", "target", "host"],
        "loopback_targets": [
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://localhost",
            "http://127.1",
            "http://2130706433",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
        ],
    },
}

def get_attack_variants(category: str, key: str, defaults: list[str]) -> list[str]:
    section = ATTACK_VARIANT_CATALOG.get(category, {})
    variants = section.get(key)
    if not isinstance(variants, list) or not variants:
        variants = list(defaults)
    return [item for item in variants if isinstance(item, str) and item.strip()]

