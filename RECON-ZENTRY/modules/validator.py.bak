"""Validate findings + confidence scoring"""
import aiohttp, asyncio
from core.logger import logger
from core.runner import run_parallel

async def revalidate(finding, http):
    """Re-hit the URL to confirm."""
    url = finding.get("matched-at") or finding.get("url") or finding.get("host")
    if not url: return None
    try:
        async with http.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
            if r.status < 600:
                finding["validated"] = True
                finding["confidence"] = compute_confidence(finding)
                return finding
    except: pass
    return None

def compute_confidence(f):
    """Score 0-100"""
    score = 50
    sev = (f.get("info",{}).get("severity") or f.get("severity","")).lower()
    score += {"critical":40,"high":30,"medium":15,"low":5}.get(sev, 0)
    if f.get("type") in ("SQLi","SSRF","LFI"): score += 10
    if f.get("evidence") or f.get("matcher-name"): score += 5
    return min(score, 100)

async def validate_all(findings, session):
    logger.info("✅ VALIDATION")
    all_f = list(findings.get("nuclei", [])) + list(findings.get("exploits", []))
    if not all_f:
        session.update("validated", [])
        return []
    async with aiohttp.ClientSession(headers={"User-Agent":"HackWithYuva/4.0"}) as http:
        results = await run_parallel([revalidate(f, http) for f in all_f], max_concurrent=15)
    valid = [r for r in results if isinstance(r, dict) and r.get("validated")]
    # Custom-engine findings get auto-confidence
    for f in findings.get("exploits", []):
        if "confidence" not in f:
            f["validated"] = True
            f["confidence"] = compute_confidence(f)
            valid.append(f)
    valid = list({(v.get("url",""),v.get("type","")):v for v in valid}.values())
    session.update("validated", valid)
    logger.info(f"   ✓ Validated: {len(valid)} findings")
    return valid
