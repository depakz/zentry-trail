import aiohttp

async def run(target: str, timeout: int = 30) -> list[str]:
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=timeout) as r:
                data = await r.json(content_type=None)
        names = set()
        for entry in data:
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(target):
                    names.add(n)
        return sorted(names)
    except Exception:
        return []
