"""
AuthManager — handles pre-scan login, session management, and credential
detection for authenticated scanning.

Security:
  - Passwords are stored in memory only, never logged or printed.
  - All log messages mask credential values as [REDACTED].
"""

import logging
import re
import requests
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("zentry.auth")

# Pre-compiled regex patterns to avoid quoting issues
_RE_PASSWORD_INPUT = re.compile(r'<input[^>]+type=[\"\x27]?password', re.I)
_RE_FORM_ACTION = re.compile(r'action=[\"\x27]([^\"\x27]+)[\"\x27]', re.I)
_RE_HIDDEN_INPUT = re.compile(r'<input[^>]+type=[\"\x27]hidden[\"\x27][^>]*>', re.I)
_RE_NAME_ATTR = re.compile(r'name=[\"\x27]([^\"\x27]+)[\"\x27]', re.I)
_RE_VALUE_ATTR = re.compile(r'value=[\"\x27]([^\"\x27]*)[\"\x27]', re.I)

# ── Login endpoint detection profiles ────────────────────────────────────────
# Maps login path patterns to form field names.
LOGIN_PROFILES = {
    "/doLogin":    {"user_field": "uid",      "pass_field": "passw"},
    "/login.jsp":  {"user_field": "uid",      "pass_field": "passw"},
    "/dologin":    {"user_field": "uid",      "pass_field": "passw"},
    "/login":      {"user_field": "username", "pass_field": "password"},
    "/auth/login": {"user_field": "username", "pass_field": "password"},
    "/signin":     {"user_field": "username", "pass_field": "password"},
    "/auth":       {"user_field": "username", "pass_field": "password"},
}

# Post-login success indicators
LOGIN_SUCCESS_INDICATORS = [
    "my account", "sign off", "logout", "welcome", "dashboard",
    "account summary", "sign out", "logoff", "altoroaccounts",
]

# Login failure / form-still-present indicators
LOGIN_FAIL_INDICATORS = [
    "invalid username", "invalid credentials", "login failed",
    "authentication failed", "incorrect password",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ZentryScanner/2.0)"}


class AuthSessionLegacy:
    """Legacy helper for orchestrator backward compatibility."""
    def __init__(self, cookies, authenticated, username, login_url, method):
        self.cookies = cookies
        self.authenticated = authenticated
        self.username = username
        self.login_url = login_url
        self.method = method


class AuthManager:
    """
    Manages pre-scan authentication and session propagation.

    Usage:
        mgr = AuthManager(target="http://target.com", credentials={"username": "admin", "password": "admin"})
        endpoint = mgr.detect_login_endpoint(endpoints)
        if mgr.login(endpoint["url"], endpoint["user_field"], endpoint["pass_field"]):
            session = mgr.get_session()  # authenticated requests.Session
    """

    def __init__(self, target: str, credentials: dict = None):
        self.session = requests.Session()
        self.target = target
        self.credentials = credentials or {}  # {"username": "...", "password": "..."}
        self.authenticated = False
        self.auth_cookies = {}

        # Support for secondary user (IDOR dual-session testing)
        self.credentials2 = {}
        self.session2 = None
        self.authenticated2 = False
        self.auth_cookies2 = {}

    @property
    def base_url(self) -> str:
        parsed = urlparse(self.target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def detect_login_endpoint(self, endpoint_patterns: list = None) -> dict:
        """
        Scan for known login paths and return the login endpoint config.

        Parameters
        ----------
        endpoint_patterns : list[str], optional
            List of discovered endpoints to scan for login paths.

        Returns
        -------
        dict with keys: url, user_field, pass_field.
        Empty dict if no login endpoint found.
        """
        base = self.base_url

        # Check known login paths
        for path, fields in LOGIN_PROFILES.items():
            url = urljoin(base, path)
            try:
                r = self.session.get(url, headers=HEADERS, verify=False, timeout=8, allow_redirects=True)
                if r.status_code == 200 and _RE_PASSWORD_INPUT.search(r.text):
                    return {
                        "url": url,
                        "user_field": fields["user_field"],
                        "pass_field": fields["pass_field"],
                    }
            except Exception:
                continue

        # Check discovered endpoints for login-like URLs
        if endpoint_patterns:
            for ep in endpoint_patterns:
                ep_lower = str(ep).lower()
                for path, fields in LOGIN_PROFILES.items():
                    if path.lower() in ep_lower:
                        url = ep if ep.startswith("http") else urljoin(base, ep)
                        return {
                            "url": url,
                            "user_field": fields["user_field"],
                            "pass_field": fields["pass_field"],
                        }

        return {}

    def _extract_form_data(self, page_text: str, login_url: str, user_field: str, pass_field: str) -> tuple:
        """Extract form action URL and hidden fields from login page HTML."""
        post_url = login_url
        action_m = _RE_FORM_ACTION.search(page_text)
        if action_m:
            post_url = urljoin(login_url, action_m.group(1))

        data = {
            user_field: self.credentials.get("username"),
            pass_field: self.credentials.get("password"),
        }
        if "btnSubmit" in page_text:
            data["btnSubmit"] = "Login"

        # Parse hidden inputs
        for hm in _RE_HIDDEN_INPUT.finditer(page_text):
            nm = _RE_NAME_ATTR.search(hm.group(0))
            vm = _RE_VALUE_ATTR.search(hm.group(0))
            if nm:
                data[nm.group(1)] = vm.group(1) if vm else ""

        return post_url, data

    def _check_login_success(self, response_text: str, user_field: str) -> tuple:
        """Check whether login succeeded or failed based on response content."""
        body_lower = response_text.lower()

        # Check for login form still present (failure indicator)
        has_login_form = (
            _RE_PASSWORD_INPUT.search(response_text)
            or f'name="{user_field}"' in response_text
            or f"name='{user_field}'" in response_text
        )

        # Check for explicit failure messages
        has_failure_msg = any(indicator in body_lower for indicator in LOGIN_FAIL_INDICATORS)

        # Check for post-login success indicators
        has_success_indicator = any(indicator in body_lower for indicator in LOGIN_SUCCESS_INDICATORS)

        return has_login_form, has_failure_msg, has_success_indicator

    def login(self, login_url: str, user_field: str, pass_field: str) -> bool:
        """
        POST credentials to login_url and detect success.

        On success: stores session cookies, sets self.authenticated = True.
        On failure: logs warning (no password in log), returns False.
        Never logs or prints password in plaintext.
        """
        if not self.credentials:
            return False
        try:
            # 1. GET login page to extract form action + hidden fields
            r_get = self.session.get(login_url, headers=HEADERS, verify=False, timeout=10)

            post_url, data = self._extract_form_data(r_get.text, login_url, user_field, pass_field)

            # 2. POST login credentials
            r = self.session.post(post_url, data=data, headers=HEADERS, verify=False, timeout=15)

            has_login_form, has_failure_msg, has_success_indicator = self._check_login_success(r.text, user_field)

            if not has_login_form and not has_failure_msg:
                self.authenticated = True
                self.auth_cookies = requests.utils.dict_from_cookiejar(self.session.cookies)
                username = self.credentials.get("username", "unknown")
                logger.info("Authentication successful as %s (password [REDACTED])", username)
                return True

            if has_success_indicator and not has_failure_msg:
                self.authenticated = True
                self.auth_cookies = requests.utils.dict_from_cookiejar(self.session.cookies)
                username = self.credentials.get("username", "unknown")
                logger.info("Authentication successful as %s (password [REDACTED])", username)
                return True

            logger.warning("Authentication failed for user '%s' (password [REDACTED])",
                           self.credentials.get("username", "unknown"))
            return False
        except Exception as exc:
            logger.warning("Authentication error: %s (credentials [REDACTED])", exc)
            return False

    def login_user2(self, login_url: str, user_field: str, pass_field: str) -> bool:
        """
        Login with secondary credentials for dual-session IDOR testing.

        Same logic as login() but uses self.credentials2 and self.session2.
        """
        if not self.credentials2:
            return False
        try:
            self.session2 = requests.Session()
            r_get = self.session2.get(login_url, headers=HEADERS, verify=False, timeout=10)

            post_url = login_url
            action_m = _RE_FORM_ACTION.search(r_get.text)
            if action_m:
                post_url = urljoin(login_url, action_m.group(1))

            data = {
                user_field: self.credentials2.get("username"),
                pass_field: self.credentials2.get("password"),
            }
            if "btnSubmit" in r_get.text:
                data["btnSubmit"] = "Login"

            for hm in _RE_HIDDEN_INPUT.finditer(r_get.text):
                nm = _RE_NAME_ATTR.search(hm.group(0))
                vm = _RE_VALUE_ATTR.search(hm.group(0))
                if nm:
                    data[nm.group(1)] = vm.group(1) if vm else ""

            r = self.session2.post(post_url, data=data, headers=HEADERS, verify=False, timeout=15)

            has_login_form, has_failure_msg, has_success_indicator = self._check_login_success(r.text, user_field)

            if (not has_login_form and not has_failure_msg) or (has_success_indicator and not has_failure_msg):
                self.authenticated2 = True
                self.auth_cookies2 = requests.utils.dict_from_cookiejar(self.session2.cookies)
                username = self.credentials2.get("username", "unknown")
                logger.info("User2 authentication successful as %s (password [REDACTED])", username)
                return True

            logger.warning("User2 authentication failed for '%s' (password [REDACTED])",
                           self.credentials2.get("username", "unknown"))
            return False
        except Exception as exc:
            logger.warning("User2 authentication error: %s (credentials [REDACTED])", exc)
            return False

    def get_session(self) -> requests.Session:
        """Return the authenticated requests.Session object.

        Validators use this session for all requests when auth is available.
        """
        return self.session

    @property
    def session_legacy(self) -> AuthSessionLegacy:
        """Helper to return legacy representation of the session for Orchestrator."""
        return AuthSessionLegacy(
            cookies=self.auth_cookies,
            authenticated=self.authenticated,
            username=self.credentials.get("username", "unknown") if self.authenticated else "",
            login_url="",
            method="form",
        )
