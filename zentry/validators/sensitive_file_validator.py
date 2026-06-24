from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urljoin

import requests
import urllib3

from zentry.session import Evidence, ValidationResult
from zentry.validators.base import BaseValidator

# Disable insecure request warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SENSITIVE_PATHS = [
    "/admin/clients.xls",
    "/admin/admin.jsp",
    "/admin/",
    "/admin/users",
    "/admin/config",
    "/v2/swagger.json",
    "/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/.env",
    "/config.php",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/web.config",
    "/server-status",
    "/server-info",
    "/actuator/env",
    "/actuator/beans",
]

SENSITIVE_CONTENT = [
    # Credit cards, SSN, financial data
    (r"\b(?:\d{4}[- ]){3}\d{4}\b", "credit card pattern"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
    # Credentials
    (r"password\s*[:=]\s*\S+", "password in file"),
    (r"api[_-]?key\s*[:=]\s*\S+", "API key"),
    (r"secret\s*[:=]\s*\S+", "secret value"),
    # Database dumps
    (r"INSERT INTO", "SQL dump"),
    (r"CREATE TABLE", "SQL schema"),
    # Admin indicators
    (r"admin panel|manage users|user management|delete user", "admin content"),
]

SENSITIVE_EXTENSIONS = (".xls", ".xlsx", ".csv", ".sql", ".bak", ".backup",
                        ".zip", ".tar", ".gz", ".env", ".log", ".config")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ZentryScanner/2.0)"}


def _get(url: str, cookies: dict = None, timeout: int = 12) -> tuple[int, str, dict]:
    try:
        r = requests.get(url, headers=HEADERS, cookies=cookies or {},
                         timeout=timeout, allow_redirects=True, verify=False)
        return r.status_code, r.text, dict(r.headers)
    except Exception:
        return 0, "", {}


def _is_sensitive(body: str, content_type: str = "") -> tuple[bool, str]:
    """Returns (is_sensitive, reason)."""
    # Binary/office files served directly
    if any(ct in content_type.lower() for ct in
           ("excel", "spreadsheet", "octet-stream", "zip", "sql")):
        return True, f"Sensitive file type served: {content_type}"
    body_lower = body.lower()
    for pattern, label in SENSITIVE_CONTENT:
        if re.search(pattern, body_lower if label in ("admin content",) else body, re.I):
            return True, f"Sensitive content: {label}"
    return False, ""


class SensitiveFileValidator(BaseValidator):
    validator_id = "sensitive_file_validator"
    priority = 88
    SIGNALS = {}  # universal — runs always

    def __init__(self, context=None):
        super().__init__()
        self.context = context

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        target_url = state.get("url") or state.get("target")
        parsed = urlsplit(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        cookies: Dict[str, str] = state.get("auth_cookies") or {}
        findings: List[ValidationResult] = []

        # ── PART C Enrichment: re-test /admin/admin.jsp using auth session
        auth_manager = state.get("auth_manager")
        if auth_manager and auth_manager.authenticated:
            session = auth_manager.get_session()
            admin_url = urljoin(base, "/admin/admin.jsp")
            try:
                r = session.get(admin_url, verify=False, timeout=8, allow_redirects=False)
                if r.status_code == 200 and ("admin" in r.text.lower() or "user" in r.text.lower() or "manage" in r.text.lower() or "administration" in r.text.lower()):
                    findings.append(ValidationResult(
                        success=True, confidence=0.95, severity="high",
                        vulnerability="sensitive-file-exposure",
                        evidence=Evidence(
                            request={"url": admin_url, "method": "GET"},
                            response={"status": r.status_code, "content_type": r.headers.get("Content-Type", ""), "snippet": r.text[:300]},
                            matched="/admin/admin.jsp",
                        ),
                        impact="Sensitive path /admin/admin.jsp is directly accessible under the current authenticated session without access controls.",
                        remediation="Restrict access to admin paths to only authorized roles; implement strict access control lists (ACLs)."
                    ))
            except Exception:
                pass

        # 1. Probe well-known sensitive paths
        for path in SENSITIVE_PATHS:
            url = urljoin(base, path)
            status, body, hdrs = _get(url, cookies)
            if status != 200 or len(body) < 50:
                continue
            ct = hdrs.get("Content-Type", "")
            sensitive, reason = _is_sensitive(body, ct)
            if sensitive:
                findings.append(ValidationResult(
                    success=True, confidence=0.92, severity="high",
                    vulnerability="sensitive-file-exposure",
                    evidence=Evidence(
                        request={"url": url, "method": "GET"},
                        response={"status": status, "content_type": ct,
                                  "snippet": body[:300]},
                        matched=path,
                    ),
                    impact=f"Sensitive file/path {path!r} is publicly accessible. {reason}.",
                    remediation="Restrict access to admin paths, remove backup/config files from web root, require authentication for admin interfaces.",
                ))
                if len(findings) >= 3:
                    break

        # 2. Check endpoints the crawler already discovered that look sensitive
        for ep in (state.get("endpoints") or [])[:200]:
            ep_lower = ep.lower()
            if not any(ep_lower.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
                continue
            ep_parsed = urlsplit(ep)
            if ep_parsed.netloc != parsed.netloc:
                continue
            status, body, hdrs = _get(ep, cookies)
            if status != 200 or len(body) < 20:
                continue
            ct = hdrs.get("Content-Type", "")
            sensitive, reason = _is_sensitive(body, ct)
            if sensitive or len(body) > 500:
                findings.append(ValidationResult(
                    success=True, confidence=0.88, severity="high",
                    vulnerability="sensitive-file-exposure",
                    evidence=Evidence(
                        request={"url": ep, "method": "GET"},
                        response={"status": status, "content_type": ct,
                                  "size_bytes": len(body), "snippet": body[:300]},
                        matched=ep,
                    ),
                    impact=f"Sensitive file {ep!r} is directly downloadable. {reason}.",
                    remediation="Remove or restrict access to sensitive files. Serve through authenticated API endpoints only.",
                ))

        # 3. Version disclosure in headers
        server_hdr = ""
        try:
            r = requests.head(base, headers=HEADERS, timeout=8, allow_redirects=True, verify=False)
            server_hdr = r.headers.get("Server", "") or r.headers.get("X-Powered-By", "")
        except Exception:
            pass
        if server_hdr and re.search(r"[\d.]{3,}", server_hdr):
            findings.append(ValidationResult(
                success=True, confidence=0.75, severity="medium",
                vulnerability="server-version-disclosure",
                evidence=Evidence(
                    request={"url": base, "method": "HEAD"},
                    response={"server_header": server_hdr},
                    matched=server_hdr,
                ),
                impact=f"Server version disclosed in HTTP header: {server_hdr!r}. Aids targeted exploitation.",
                remediation="Configure server to suppress version information from HTTP headers.",
            ))

        if findings:
            return findings if len(findings) > 1 else findings[0]
        return None
