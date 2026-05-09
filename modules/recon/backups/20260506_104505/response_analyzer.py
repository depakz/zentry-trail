"""Response analysis - reflection / errors / anomalies (ML-ready)"""
import aiohttp, asyncio, re
from core.logger import logger
from core.runner import run_parallel

ERROR_SIGNATURES = {
    "sql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
            r"ORA-\d{5}", r"Microsoft.*ODBC.*SQL Server", r"sqlite3.OperationalError"],
    "php": [r"<b>Warning</b>:", r"<b>Fatal error</b>:", r"on line \d+"],
    "stack_trace": [r"at [\w\.]+\(.*\.java:\d+\)", r"Traceback \(most recent call last\)"],
    "debug": [r"DEBUG\s*=\s*True", r"Exception details", r"X-Debug-Token"],
}

REFLECT_PROBE = "yuvaProbe9173"

async def analyze_one(url, http):
    out = {"url": url, "reflected": False, "errors": [], "status": None, "size": 0, "anomalies": []}
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}xtest={REFLECT_PROBE}"
    try:
        async with http.get(test_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
            body = await r.text(errors="ignore")
            out["status"] = r.status
            out["size"] = len(body)
            if REFLECT_PROBE in body:
                out["reflected"] = True
            for cat, sigs in ERROR_SIGNATURES.items():
                for s in sigs:
                    if re.search(s, body, re.I):
                        out["errors"].append(cat)
                        break
            if r.status >= 500: out["anomalies"].append("server_error")
            if "Set-Cookie" in r.headers and "HttpOnly" not in r.headers.get("Set-Cookie",""):
                out["anomalies"].append("cookie_no_httponly")
    except Exception as e:
        out["anomalies"].append(f"err:{type(e).__name__}")
    return out

async def analyze(urls, session):
    logger.info("🧠 RESPONSE ANALYZER")
    if not urls:
        return []
    sample = urls[:50]
    async with aiohttp.ClientSession(headers={"User-Agent":"HackWithYuva/4.0"}) as http:
        results = await run_parallel([analyze_one(u, http) for u in sample], max_concurrent=15)
    clean = [r for r in results if isinstance(r, dict)]
    reflected = [r for r in clean if r["reflected"]]
    errored   = [r for r in clean if r["errors"]]
    logger.info(f"   ✓ Reflections: {len(reflected)} | Errors leaked: {len(errored)}")
    session.update("anomalies", clean)
    return clean
