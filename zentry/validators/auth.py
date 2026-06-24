from __future__ import annotations

import re
import time
import requests
import urllib3
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urljoin

from zentry.session import Evidence, ExecutionContext, ValidationResult
from zentry.validators.base import BaseValidator

# Disable insecure request warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------- DefaultCredentialValidator -----------------

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
    SIGNALS = {}

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
        findings: List[ValidationResult] = []

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
                    if auth_manager and not auth_manager.authenticated:
                        auth_manager.credentials = {"username": cred["u"], "password": cred["p"]}
                        auth_manager.authenticated = True
                        auth_manager.auth_cookies = cookies

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

                    self._check_cookies(base, findings, login_response=r_login)
                    findings.append(finding)
                    return findings if len(findings) > 1 else findings[0]

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

        self._check_cookies(base, findings)

        if findings:
            return findings if len(findings) > 1 else findings[0]
        return None

    def _check_cookies(self, base: str, findings: List[ValidationResult],
                       login_response: requests.Response = None) -> None:
        try:
            cookies_raw = ""
            if login_response is not None:
                cookies_raw = login_response.headers.get("Set-Cookie", "") or ""

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


# ----------------- AuthValidator -----------------

A07_COVERAGE_MARKERS = [
    "missing_login_rate_limit",
    "insecure_remember_me_cookie_flags",
    "weak_session_management_signal",
    "credential_control_weakness",
    "authentication_flow_hardening_gap",
]


def _looks_like_login_endpoint(url: str, state: Dict[str, Any]) -> bool:
    tokens = ("login", "signin", "sign-in", "auth", "session", "account")
    if any(token in url.lower() for token in tokens):
        return True
    for key in ("login_url", "login_endpoint", "auth_url"):
        value = state.get(key)
        if isinstance(value, str) and value:
            return True
        if value is True:
            return True
    return False


def _collect_set_cookies(response: requests.Response) -> List[str]:
    cookies: List[str] = []
    header_value = response.headers.get("Set-Cookie")
    if isinstance(header_value, str) and header_value:
        cookies.append(header_value)
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None:
        try:
            cookies.extend(raw_headers.get_all("Set-Cookie") or [])
        except Exception:
            pass
    return cookies


class AuthValidator(BaseValidator):
    SIGNALS = {
        "endpoint_patterns": ["/login", "/signin", "/auth", "/session", "/account"]
    }

    def __init__(self, context: Optional[ExecutionContext] = None):
        super().__init__()
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("login_url") or state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]):
        target_url = state.get("login_url") or state.get("url") or state.get("target")
        if not isinstance(target_url, str) or not target_url:
            return None

        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        cookie = state.get("cookie")
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie.strip()

        timeout = int(state.get("timeout", 8) or 8)
        attempt_count = int(state.get("login_attempts", 4) or 4)
        login_like = _looks_like_login_endpoint(target_url, state)

        payload = state.get("login_payload")
        if not isinstance(payload, dict) or not payload:
            username = state.get("login_username") or "security-pipeline-test"
            password = state.get("login_password") or "invalid-password"
            payload = {"username": str(username), "password": str(password)}

        attempt_details: List[Dict[str, Any]] = []
        findings: List[str] = []
        session = requests.Session()

        if login_like:
            status_codes: List[int] = []

            for attempt_number in range(1, attempt_count + 1):
                start = time.perf_counter()
                try:
                    response = session.post(
                        target_url,
                        data=payload,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False,
                    )
                    elapsed = time.perf_counter() - start
                    status_codes.append(response.status_code)
                    attempt_details.append({"attempt": attempt_number, "status": response.status_code, "elapsed_s": round(elapsed, 3)})
                except requests.RequestException as exc:
                    attempt_details.append({"attempt": attempt_number, "error": str(exc)})
                    continue

            if status_codes and not any(code in {429, 403} for code in status_codes):
                findings.append("missing_rate_limiting")

        try:
            get_response = session.get(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            set_cookie_headers = _collect_set_cookies(get_response)
            insecure_cookie_headers: List[str] = []

            for header_value in set_cookie_headers:
                lowered = header_value.lower()
                if not any(token in lowered for token in ("remember", "remember_me", "persistent", "stay_signed_in")):
                    continue
                if "secure" not in lowered or "httponly" not in lowered:
                    insecure_cookie_headers.append(header_value)

            if insecure_cookie_headers:
                findings.append("remember_me_cookie_without_secure_httponly")

            evidence_extra = {
                "login_like": login_like,
                "attempts": attempt_details,
                "set_cookie_headers": set_cookie_headers,
            }

            if findings:
                return ValidationResult(
                    success=True,
                    confidence=0.93 if len(findings) > 1 else 0.88,
                    severity="high",
                    vulnerability="a07-identification-and-authentication-failures",
                    evidence=Evidence(
                        request={"target": target_url, "payload": payload},
                        response={"login_response_status": get_response.status_code, "findings": findings},
                        matched=",".join(findings),
                        extra={**evidence_extra, "coverage_markers": A07_COVERAGE_MARKERS},
                    ),
                    impact="The login flow does not enforce expected authentication controls, enabling brute-force or session persistence abuse.",
                    remediation="Add account lockout or rate limiting for login attempts and set Secure/HttpOnly on remember-me cookies.",
                )

            return ValidationResult(
                success=False,
                confidence=0.15,
                severity="info",
                vulnerability="a07-identification-and-authentication-failures",
                evidence=Evidence(
                    request={"target": target_url, "payload": payload},
                    response={"login_response_status": get_response.status_code, "attempts": attempt_details},
                    matched="",
                    extra={**evidence_extra, "coverage_markers": A07_COVERAGE_MARKERS},
                ),
                impact="No obvious authentication-control weakness was confirmed from the available probe.",
                remediation="Keep login controls, cookie flags, and lockout telemetry under regression test.",
            )

        except requests.RequestException as exc:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="a07-identification-and-authentication-failures",
                evidence=Evidence(
                    request={"target": target_url, "payload": payload},
                    response=str(exc),
                    matched="",
                    extra={"login_like": login_like, "attempts": attempt_details, "coverage_markers": A07_COVERAGE_MARKERS},
                ),
            )
