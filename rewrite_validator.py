import sys

with open('modules/recon/modules/validator.py', 'r') as f:
    content = f.read()

# Add aiohttp and asyncio semaphore
content = content.replace("import logging, re, asyncio\nimport requests\nimport urllib3", 
"""import logging, re, asyncio
import requests
import aiohttp
import urllib3""")

old_probe = """def _probe(url, timeout=10):
    if not url:
        return None, 0
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=False, headers=UA)
        return r.text, r.status_code
    except Exception as e:
        log.debug(f"validator probe failed: {url} → {e}")
        return None, 0"""

new_probe = """async def _probe(url, session, timeout=10):
    if not url:
        return None, 0
    try:
        async with session.get(url, timeout=timeout, allow_redirects=False, headers=UA, ssl=False) as r:
            body = await r.text()
            return body, r.status
    except Exception as e:
        log.debug(f"validator probe failed: {url} → {e}")
        return None, 0"""

content = content.replace(old_probe, new_probe)

old_confidence = """def _confidence(finding):
    \"\"\"
    Return (confidence_score, validated_bool, reason).
    confidence_score: 0–100
    \"\"\"
    url = finding.get("url", "") or finding.get("test_url", "")
    ftype = (finding.get("type") or "").lower()

    # Probe the target
    body, status = _probe(url)
    if body is None:
        return 0, False, "unreachable\"\"\""""

new_confidence = """async def _confidence(finding, session, sem):
    \"\"\"
    Return (confidence_score, validated_bool, reason).
    confidence_score: 0–100
    \"\"\"
    url = finding.get("url", "") or finding.get("test_url", "")
    ftype = (finding.get("type") or "").lower()

    # Early exit logic is implicit: we evaluate and return immediately
    async with sem:
        # Probe the target
        body, status = await _probe(url, session)
    if body is None:
        return 0, False, "unreachable\"\"\""""

content = content.replace(old_confidence, new_confidence)

old_validate_all = """    loop = asyncio.get_event_loop()
    validated = []
    high_conf = 0
    for f in flat:
        score, ok, reason = await loop.run_in_executor(None, _confidence, f)
        f["confidence"] = score
        f["validated"] = ok
        f["reason"] = reason
        if ok:
            high_conf += 1
        validated.append(f)"""

new_validate_all = """    validated = []
    high_conf = 0
    sem = asyncio.Semaphore(20) # Limit concurrent requests
    
    async with aiohttp.ClientSession() as http_session:
        tasks = [_confidence(f, http_session, sem) for f in flat]
        results = await asyncio.gather(*tasks)
        
        for f, (score, ok, reason) in zip(flat, results):
            f["confidence"] = score
            f["validated"] = ok
            f["reason"] = reason
            if ok:
                high_conf += 1
            validated.append(f)"""

content = content.replace(old_validate_all, new_validate_all)

with open('modules/recon/modules/validator.py', 'w') as f:
    f.write(content)
