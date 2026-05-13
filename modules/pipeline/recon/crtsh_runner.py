import aiohttp
from core.logger import dashboard

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
        results = sorted(names)
        try:
            dashboard.advance_recon("crt.sh finished")
        except Exception:
            pass
        return results
    except Exception:
        try:
            dashboard.advance_recon("crt.sh failed")
        except Exception:
            pass
        return []
