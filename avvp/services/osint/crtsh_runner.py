import httpx
from typing import List

class CRTSHRunner:
    BASE = "https://crt.sh"

    async def run(self, domain: str) -> List[str]:
        q = f"%25.{domain}"
        url = f"{self.BASE}/?q={q}&output=json"
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.get(url)
            except Exception:
                return []
            if r.status_code != 200:
                return []
            try:
                data = r.json()
            except Exception:
                return []
        names = set()
        for item in data:
            name = item.get("name_value")
            if name:
                # crt.sh may return newline-separated names
                for part in name.split('\n'):
                    names.add(part.strip())
        return sorted(names)
