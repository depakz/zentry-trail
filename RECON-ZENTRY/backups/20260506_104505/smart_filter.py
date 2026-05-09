"""Smart URL prioritization with vulnerability scoring"""
import re
from urllib.parse import urlparse, parse_qs
from config.settings import HIGH_VALUE_PARAMS, VULN_KEYWORDS
from core.logger import logger

def score_url(url):
    """Score URL by vulnerability potential (0-100)"""
    score = 0
    tags = set()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    pname_set = {p.lower() for p in params}

    # Param-based scoring
    for p in pname_set:
        if p in HIGH_VALUE_PARAMS:
            score += 15
        for vuln, keys in VULN_KEYWORDS.items():
            if p in keys:
                score += 10
                tags.add(vuln)

    # Path-based bonuses
    path = parsed.path.lower()
    if any(x in path for x in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
        score += 20; tags.add("api")
    if any(x in path for x in ["/admin", "/login", "/auth", "/oauth"]):
        score += 25; tags.add("auth")
    if any(x in path for x in ["/upload", "/file", "/import"]):
        score += 30; tags.add("upload")
    if path.endswith((".php", ".asp", ".aspx", ".jsp")):
        score += 15
    if any(x in path for x in ["redirect", "proxy", "fetch"]):
        score += 20; tags.add("ssrf")

    # Number of params
    if len(params) >= 3:
        score += 10

    return min(score, 100), list(tags)

def filter_and_rank(urls):
    """Return ranked list with scores+tags"""
    ranked = []
    for u in set(urls):
        s, tags = score_url(u)
        if s > 0:
            ranked.append({"url": u, "score": s, "tags": tags})
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked

def categorize(ranked):
    """Categorize by vuln type for targeted scanning"""
    cats = {"xss": [], "sqli": [], "ssrf": [], "lfi": [], "openredirect": [], "api": [], "auth": [], "upload": [], "other": []}
    for r in ranked:
        placed = False
        for tag in r["tags"]:
            if tag in cats:
                cats[tag].append(r["url"])
                placed = True
        if not placed:
            cats["other"].append(r["url"])
    return cats

def summarize(ranked, session):
    cats = categorize(ranked)
    logger.info("🎯 SMART FILTER RESULTS:")
    for k, v in cats.items():
        if v:
            logger.info(f"   ├─ {k.upper():13s}: {len(v)} URLs")
    session.update("prioritized", ranked)
    session.data["categorized"] = cats
    session.save()
    return cats
