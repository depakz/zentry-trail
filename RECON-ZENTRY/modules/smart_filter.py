"""
smart_filter.py — YUVA Precision Edition
Categorize + score URLs.
- HIGH priority: login, auth, password reset, redirect, dynamic+param
- LOW priority: static, images, fonts
"""
import logging
from urllib.parse import urlparse

log = logging.getLogger(__name__)

CATEGORY_RULES = {
    "AUTH":         ("login","signin","logon","auth","sso","oauth","register","signup"),
    "PASSWORD":     ("password","reset","forgot","recover"),
    "OPENREDIRECT": ("redirect","url=","next=","return=","returnurl","goto=","dest="),
    "SQLI_CANDID":  ("id=","user=","pid=","cat=","page=","item=","prod="),
    "FILE":         ("file=","path=","doc=","include=","dir=","load="),
    "API":          ("/api/","/v1/","/v2/","/rest/",".json"),
    "ADMIN":        ("admin","manager","panel","dashboard","console"),
    "UPLOAD":       ("upload","import","file"),
}

STATIC_EXT = ('.png','.jpg','.jpeg','.gif','.ico','.svg','.css','.woff',
              '.woff2','.ttf','.eot','.map','.webp','.mp4','.mp3')

DYNAMIC_EXT = ('.php','.aspx','.asp','.jsp','.do','.action','.cgi')

def _score(url):
    u = url.lower()
    path = urlparse(u).path
    score = 0

    if path.endswith(STATIC_EXT):
        return -100
    if path.endswith(DYNAMIC_EXT):
        score += 30
    if '?' in url:
        score += 25
    if any(k in u for k in ("login","signin","auth")):
        score += 50
    if any(k in u for k in ("password","reset","forgot")):
        score += 60
    if any(k in u for k in ("admin","panel","manager")):
        score += 40
    if any(k in u for k in ("redirect","url=","next=","return=")):
        score += 35
    if any(k in u for k in ("upload","import")):
        score += 30
    if "/api/" in u or u.endswith(".json"):
        score += 20
    return score

def _categorize(url):
    u = url.lower()
    cats = []
    for cat, keys in CATEGORY_RULES.items():
        if any(k in u for k in keys):
            cats.append(cat)
    return cats or ["OTHER"]

def filter_and_rank(urls):
    seen = set()
    ranked = []
    for u in urls:
        if not u or u in seen:
            continue
        seen.add(u)
        s = _score(u)
        if s < 0:
            continue
        ranked.append({"url": u, "score": s, "cats": _categorize(u)})
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked

def summarize(ranked, session):
    cats = {}
    for r in ranked:
        for c in r["cats"]:
            cats.setdefault(c, []).append(r["url"])
    log.info("🎯 SMART FILTER RESULTS:")
    for c, items in sorted(cats.items(), key=lambda x: -len(x[1])):
        log.info(f"   ├─ {c:<13}: {len(items)} URLs")
    try: session.update("categorized", cats)
    except Exception: pass
    return cats
