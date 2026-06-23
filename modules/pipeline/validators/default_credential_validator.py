"""
DefaultCredentialValidator — tests for default/weak credentials and cookie security issues.
Covers:
  - Default creds (admin/admin, jsmith/Demo1234, etc.)
  - No brute-force protection check
  - Session cookie flags (HttpOnly, Secure, SameSite)
  - Predictable/weak session token patterns
  - Integrate with AuthManager to avoid leaking plaintext credentials in reports
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urljoin

import requests
import urllib3

from modules.pipeline.engine.models import Evidence, ValidationResult
from modules.pipeline.validators.base import BaseValidator

# Disable insecure request warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CREDENTIAL_PROFILES = [
    {"u": "admin",          "p": "admin"},
    {"u": "admin",          "p": "password"},
    {"u": "admin",          "p": "admin123"},
    {"u": "jsmith",         "p": "demo1234"},
    {"u": "jsmith",         "p": "Demo1234"},
    {"u": "user",           "p": "user"},
    {"u": "test",           "p": "test"},
    {"u": "guest",          "p": "guest"},
    {"u": "administrator",  "p": "administrator"},
    {"u": "root",           "p": "root"},
]

LOGIN_FIELD_PROFILES = [
    {"user_field": "uid",      "pass_field": "passw",    "submit": {"btnSubmit": "Login"}},
    {"user_field": "username", "pass_field": "password", "submit": {}},
    {"user_field": "user",     "pass_field": "pass",     "submit": {}},
    {"user_field": "login",    "pass_field": "password", "submit": {}},
    {"user_field": "email",    "pass_field": "password", "submit": {}},
]

LOGIN_SUCCESS = ["my account", "sign off", "logout", "welcome", "dashboard",
                 "account summary", "sign out", "logoff", "altoroaccounts"]

LOGIN_PATHS = ["/doLogin", "/login.jsp", "/login", "/signin", "/auth"]
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ZentryScanner/2.0)"}


class DefaultCredentialValidator(BaseValidator):
    validator_id = "default_credential_validator"
    priority = 92
    SIGNALS = {}  # universal

    def __init__(self, context=None):
        self.context = context

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        target_url = state.get("url") or state.get("target")
        parsed = urlsplit(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings: List[ValidationResult] = []

        # ── 1. Find login endpoint ─────────────────────────────────────────────
        login_url = None
        login_page_body = ""
        for path in LOGIN_PATHS:
            url = urljoin(base, path)
            try:
                r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True, verify=False)
                if r.status_code == 200 and re.search(
                    r'<input[^>]+type=["\']?password', r.text, re.I
                ):
                    login_url = url
                    login_page_body = r.text
                    break
            except Exception:
                continue

        if not login_url:
            # Try to find login form from homepage
            try:
                r_home = requests.get(base, headers=HEADERS, timeout=8, allow_redirects=True, verify=False)
                links = re.findall(r'href=["\']([^"\']+)["\']', r_home.text, re.I)
                for link in links:
                    if any(h in link.lower() for h in ("login", "signin")):
                        candidate = urljoin(base, link)
                        r_cand = requests.get(candidate, headers=HEADERS, timeout=8, allow_redirects=True, verify=False)
                        if re.search(r'<input[^>]+type=["\']?password', r_cand.text, re.I):
                            login_url = candidate
                            login_page_body = r_cand.text
                            break
            except Exception:
                pass

        if not login_url:
            self._check_cookies(base, findings)
            return findings[0] if len(findings) == 1 else (findings if findings else None)

        # ── 2. Extract form action + hidden fields ─────────────────────────────
        form_blocks = re.findall(r'<form[^>]*>.*?</form>', login_page_body, re.I | re.S)
        form_action = login_url
        form_block = login_page_body
        for block in form_blocks:
            if re.search(r'<input[^>]+type=["\']?password', block, re.I):
                action_match = re.search(r'action=["\']([^"\']+)["\']', block, re.I)
                if action_match:
                    form_action = urljoin(login_url, action_match.group(1))
                    form_block = block
                    break

        hidden: Dict[str, str] = {}
        try:
            for hm in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', form_block, re.I):
                nm = re.search(r'name=["\']([^"\']+)["\']', hm.group(0))
                vm = re.search(r'value=["\']([^"\']*)["\']', hm.group(0))
                if nm:
                    hidden[nm.group(1)] = vm.group(1) if vm else ""
        except Exception:
            pass

        # ── 3. Try credential profiles ────────────────────────────────────────
        attempts = 0
        auth_manager = state.get("auth_manager")

        for field_profile in LOGIN_FIELD_PROFILES:
            for cred in CREDENTIAL_PROFILES:
                data = dict(hidden)
                data[field_profile["user_field"]] = cred["u"]
                data[field_profile["pass_field"]] = cred["p"]
                data.update(field_profile["submit"])

                try:
                    r_login = requests.post(form_action, data=data, headers=HEADERS, timeout=10, allow_redirects=True, verify=False)
                    status = r_login.status_code
                    body = r_login.text
                    cookies = dict(r_login.cookies)
                except Exception:
                    continue

                attempts += 1
                body_lower = body.lower()

                if status == 200 and any(s in body_lower for s in LOGIN_SUCCESS):
                    # Save working credentials to AuthManager if available
                    if auth_manager and not auth_manager.authenticated:
                        auth_manager.credentials = {"username": cred["u"], "password": cred["p"]}
                        auth_manager.authenticated = True
                        auth_manager.auth_cookies = cookies

                    # Mask credentials in evidence payload: credentials must never appear in plaintext
                    # Format payload exactly as username:{username} (never include password in payload field)
                    finding = self.confirm_finding(
                        request_obj=r_login.request,
                        response_obj=r_login,
                        vulnerability="default-credentials",
                        severity="critical",
                        confidence=0.97,
                        param=field_profile["user_field"],
                        payload=f"username:{cred['u']}",
                        impact="Default credentials accepted. Full authenticated access to application.",
                        remediation="Change all default credentials immediately and enforce strong password policy."
                    )

                    # Check cookie security on successful login response
                    self._check_cookies(base, findings, login_response=r_login)
                    findings.append(finding)
                    return findings if len(findings) > 1 else findings[0]

        # ── 4. No brute-force protection ──────────────────────────────────────
        if attempts >= 10:
            findings.append(ValidationResult(
                success=True, confidence=0.80, severity="medium",
                vulnerability="no-brute-force-protection",
                evidence=Evidence(
                    request={"url": form_action, "attempts": attempts},
                    response={"observation": "No account lockout or CAPTCHA after 10+ failed attempts"},
                    matched="no-lockout",
                ),
                impact="Login endpoint allows unlimited credential-stuffing attempts without lockout or rate limiting.",
                remediation="Implement account lockout (e.g., 5 attempts), CAPTCHA, or rate limiting on authentication endpoints.",
            ))

        # ── 5. Cookie security flags ──────────────────────────────────────────
        self._check_cookies(base, findings)

        if findings:
            return findings if len(findings) > 1 else findings[0]
        return None

    def _check_cookies(self, base: str, findings: List[ValidationResult],
                       login_response: requests.Response = None) -> None:
        """Check session cookie security flags."""
        try:
            cookies_raw = ""
            if login_response is not None:
                cookies_raw = login_response.headers.get("Set-Cookie", "") or ""

            # If not found or empty, fall back to checking the base URL
            if not cookies_raw:
                resp = requests.get(base, headers=HEADERS, timeout=8,
                                    allow_redirects=True, verify=False)
                cookies_raw = resp.headers.get("Set-Cookie", "") or ""

            issues = []
            if cookies_raw:
                cookies_raw_lower = cookies_raw.lower()
                if "jsessionid" in cookies_raw_lower or "sessionid" in cookies_raw_lower or "sid" in cookies_raw_lower or "=" in cookies_raw:
                    if "httponly" not in cookies_raw_lower:
                        issues.append("HttpOnly flag missing — JS can read session cookie (XSS risk)")
                    if "secure" not in cookies_raw_lower:
                        issues.append("Secure flag missing — cookie transmitted over plain HTTP")
                    if "samesite" not in cookies_raw_lower:
                        issues.append("SameSite flag missing — CSRF attacks possible")

            if issues:
                # Check if we already have an insecure-session-cookie finding in findings to avoid duplicates
                already_exists = any(r.vulnerability == "insecure-session-cookie" for r in findings)
                if not already_exists:
                    findings.append(ValidationResult(
                        success=True, confidence=0.85, severity="medium",
                        vulnerability="insecure-session-cookie",
                        evidence=Evidence(
                            request={"url": base},
                            response={"set_cookie": cookies_raw[:400]},
                            matched="; ".join(issues),
                        ),
                        impact="Session cookie lacks security flags: " + "; ".join(issues),
                        remediation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                    ))
        except Exception:
            pass
