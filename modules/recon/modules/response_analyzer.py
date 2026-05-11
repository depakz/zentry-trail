"""
response_analyzer.py — YUVA Precision Edition
Detects reflections + error leaks AND stores reflective URLs
so the exploiter can target them precisely.
"""
import logging, re, asyncio
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import dashboard

log = logging.getLogger(__name__)

CANARY = "yuvaXSS9182"
ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning.*mysqli?_", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Microsoft.*ODBC.*SQL Server", re.I),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"Stack trace:", re.I),
    re.compile(r"Traceback \(most recent call last\)", re.I),
]

def _inject(url, value):
    """Replace each param value with canary, return list of mutated URLs."""
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if not qs:
        return []
    out = []
    for key in qs:
        new = {k: v[:] for k, v in qs.items()}
        new[key] = [value]
        out.append((key, urlunparse(p._replace(query=urlencode(new, doseq=True)))))
    return out

def _probe(url, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=False,
                         headers={'User-Agent':'Mozilla/5.0 YUVA'})
        return r.text, r.status_code
    except Exception:
        return "", 0

async def analyze(urls, session):
    log.info("🧠 RESPONSE ANALYZER (reflection-aware)")
    reflective = []   # URLs whose params reflect input
    errors     = []   # URLs leaking error stack traces

    loop = asyncio.get_event_loop()
    for url in urls[:60]:
        mutations = _inject(url, CANARY)
        if not mutations:
            continue
        for param, mut_url in mutations:
            body, code = await loop.run_in_executor(None, _probe, mut_url)
            if not body:
                continue
            if CANARY in body:
                reflective.append({"url": url, "param": param,
                                   "test_url": mut_url, "status": code})
            for pat in ERROR_PATTERNS:
                if pat.search(body):
                    errors.append({"url": url, "param": param,
                                   "pattern": pat.pattern, "status": code})
                    break

    log.info(f"   ✓ Reflections: {len(reflective)} | Errors leaked: {len(errors)}")
    try:
        dashboard.advance_validation(f"analyzer:reflect:{len(reflective)}")
    except Exception:
        pass
    try:
        session.update("reflections", reflective)
        session.update("error_leaks", errors)
    except Exception: pass
    try:
        dashboard.advance_validation(f"analyzer:errors:{len(errors)}")
    except Exception:
        pass
    return {"reflections": reflective, "errors": errors}
