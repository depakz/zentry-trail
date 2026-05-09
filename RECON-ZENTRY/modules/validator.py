"""
validator.py — YUVA Precision Edition
- Handles findings as dicts OR strings
- Re-probes targets to confirm real signal
- Filters out timeouts / network errors / blank responses
- Adds confidence scores
"""
import logging, re, asyncio
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

UA = {"User-Agent": "Mozilla/5.0 YUVA-Validator"}

# Known SQL/PHP/Stack error signatures (high confidence)
SQL_ERR = re.compile(
    r"(SQL syntax.*MySQL|mysqli?_|PostgreSQL.*ERROR|ORA-\d{5}|"
    r"Microsoft.*ODBC.*SQL Server|SqlException|Unclosed quotation mark|"
    r"Stack trace:|Traceback \(most recent call last\))",
    re.I)

XSS_REFLECT = re.compile(r"<script>|onerror=|javascript:", re.I)


def _ensure_dict(item, default_type="generic"):
    """Coerce a finding to dict shape with at least {url, type}."""
    if isinstance(item, dict):
        d = dict(item)
    elif isinstance(item, str):
        d = {"url": item, "type": default_type, "raw": item}
    else:
        d = {"url": str(item), "type": default_type}
    d.setdefault("type", default_type)
    d.setdefault("url", "")
    return d


def _probe(url, timeout=10):
    if not url:
        return None, 0
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=False, headers=UA)
        return r.text, r.status_code
    except Exception as e:
        log.debug(f"validator probe failed: {url} → {e}")
        return None, 0


def _confidence(finding):
    """
    Return (confidence_score, validated_bool, reason).
    confidence_score: 0–100
    """
    url = finding.get("url", "") or finding.get("test_url", "")
    ftype = (finding.get("type") or "").lower()

    # Probe the target
    body, status = _probe(url)
    if body is None:
        return 0, False, "unreachable"

    # Type-specific checks
    if "sql" in ftype:
        if SQL_ERR.search(body):
            return 95, True, "SQL error pattern matched"
        # If exploiter already provided evidence keep it but lower confidence
        if finding.get("evidence") and SQL_ERR.search(finding["evidence"]):
            return 80, True, "evidence contains SQL error"
        return 30, False, "no SQL error in response"

    if "xss" in ftype:
        # Dalfox-style finding usually has 'poc' or 'payload'
        poc = finding.get("poc") or finding.get("payload") or ""
        if poc and poc in body:
            return 90, True, "payload reflected in body"
        if XSS_REFLECT.search(body):
            return 60, True, "XSS sink detected"
        return 25, False, "no reflection"

    if "nuclei" in ftype or "info" in ftype or finding.get("template-id"):
        sev = (finding.get("severity") or "").lower()
        if sev in ("critical", "high"):
            return 85, True, f"nuclei {sev}"
        if sev == "medium":
            return 60, True, "nuclei medium"
        return 35, False, f"nuclei {sev or 'low/info'}"

    # Generic: keep if URL is alive AND status is interesting
    if status in (200, 401, 403, 500):
        return 40, False, f"alive ({status})"
    return 10, False, f"status {status}"


async def validate_all(findings_dict, session):
    """
    findings_dict: {"nuclei": [...], "exploits": {...}}  (any shape)
    """
    log.info("✅ VALIDATION (precision)")

    # Flatten everything to a list of dicts
    flat = []

    nuclei = findings_dict.get("nuclei", []) or []
    for f in nuclei:
        d = _ensure_dict(f, default_type="nuclei")
        flat.append(d)

    exploits = findings_dict.get("exploits", {}) or {}
    if isinstance(exploits, dict):
        for kind, items in exploits.items():
            for it in (items or []):
                d = _ensure_dict(it, default_type=kind)
                flat.append(d)
    elif isinstance(exploits, list):
        for it in exploits:
            d = _ensure_dict(it, default_type="exploit")
            flat.append(d)

    if not flat:
        log.info("   └─ Nothing to validate")
        try: session.update("validated", [])
        except Exception: pass
        return []

    log.info(f"   ├─ Re-probing {len(flat)} findings...")

    loop = asyncio.get_event_loop()
    validated = []
    high_conf = 0
    for f in flat:
        score, ok, reason = await loop.run_in_executor(None, _confidence, f)
        f["confidence"] = score
        f["validated"] = ok
        f["reason"] = reason
        if ok:
            high_conf += 1
        validated.append(f)

    # Sort by confidence
    validated.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    log.info(f"   ├─ Validated (high confidence): {high_conf}/{len(flat)}")
    if high_conf:
        for f in validated[:10]:
            if f["validated"]:
                log.info(f"   │  ✓ [{f['confidence']}] {f['type']:<8} "
                         f"{f['url'][:80]} ({f['reason']})")
    log.info(f"   └─ Validation complete")

    try:
        session.update("validated", validated)
        session.update("high_confidence_count", high_conf)
    except Exception:
        pass

    return validated
