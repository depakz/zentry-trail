import re, aiohttp

ENDPOINT_RE = re.compile(r'["\'](/[a-zA-Z0-9_\-/.?=&]{3,})["\']')
SECRET_RE = re.compile(
    r'(?i)(api[_-]?key|secret|token|aws_access|password)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{12,})["\']'
)

async def parse(js_url: str) -> dict:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(js_url, timeout=30) as r:
                content = await r.text()
        return {
            "endpoints": list(set(ENDPOINT_RE.findall(content))),
            "secrets":   [{"key": m[0], "value": m[1][:6]+"..."} for m in SECRET_RE.findall(content)],
        }
    except Exception:
        return {"endpoints": [], "secrets": []}
