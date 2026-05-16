"""
Real XSS validation using Playwright headless Chromium.
A finding is ONLY confirmed when the injected payload triggers a JS dialog.
"""
import asyncio
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.async_api import async_playwright
from core.adaptive_exploit_engine import compute_reward, AdaptiveExploitEngine
from .registry import register
from core.local_payload_engine import suggest_payloads

PAYLOADS = [
    "<script>window.__xss_pwn=1</script>",
    "\"><svg/onload=window.__xss_pwn=1>",
    "javascript:window.__xss_pwn=1",
    "<img src=x onerror=window.__xss_pwn=1>",
]

_playwright_instance = None
_browser_instance = None
_browser_lock = asyncio.Lock()
_sem = asyncio.Semaphore(5)

async def _get_browser():
    global _playwright_instance, _browser_instance
    async with _browser_lock:
        if _browser_instance is None:
            _playwright_instance = await async_playwright().start()
            _browser_instance = await _playwright_instance.chromium.launch(headless=True)
    return _browser_instance

@register("xss")
async def validate_xss(url: str, param: str, timeout: int = 20) -> dict | None:
    """
    Returns confirmed finding dict or None.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    browser = await _get_browser()
    _engine = AdaptiveExploitEngine()

    qs[param] = ["test"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    async with _sem:
        baseline_ctx = await browser.new_context()
        baseline_page = await baseline_ctx.new_page()
        baseline_start = time.monotonic()
        baseline_body = ""
        try:
            await baseline_page.goto(baseline_url, timeout=timeout * 1000, wait_until="domcontentloaded")
            baseline_body = await baseline_page.content()
        except Exception:
            pass
        finally:
            await baseline_ctx.close()
    baseline_time = time.monotonic() - baseline_start

    payloads = suggest_payloads("xss", n=20) or PAYLOADS
    for payload in payloads:
        qs[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        async with _sem:
            ctx = await browser.new_context()
            page = await ctx.new_page()

            executed = {"flag": False}
            # Catch dialogs (confirms execution)
            page.on("dialog", lambda d: (executed.update(flag=True), asyncio.create_task(d.dismiss())))

            response_body = ""
            status_code = 0
            response_time = 0.0
            waf = "unknown"
            try:
                start = time.monotonic()
                response = await page.goto(test_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                response_time = time.monotonic() - start
                if response is not None:
                    status_code = response.status
                # Probe the injected sentinel
                pwn = await page.evaluate("() => window.__xss_pwn === 1")
                response_body = await page.content()
                waf = "blocked" if status_code == 403 or "blocked" in response_body.lower() else "unknown"
                if pwn or executed["flag"]:
                    _engine.record_result(payload, "xss", reward=1.0, waf=waf, tech=[])
                    return {
                        "validated": True,
                        "type": "Reflected XSS",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": "JS sentinel triggered in headless browser",
                        "response_snippet": response_body[:500],
                    }
                if waf == "blocked":
                    reward = 0.0
                else:
                    reward = compute_reward(
                        validated=False,
                        response_time=response_time,
                        baseline_time=baseline_time,
                        response_body=response_body,
                        baseline_body=baseline_body,
                        status_code=status_code,
                        waf_blocked=False,
                        payload=payload,
                    )
                _engine.record_result(payload, "xss", reward=reward, waf=waf, tech=[])
            except Exception:
                pass
            finally:
                await ctx.close()
    return None  # No FP — discarded
