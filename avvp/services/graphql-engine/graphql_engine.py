from typing import Dict, Any
import httpx

class GraphQLEngine:
    def __init__(self):
        pass

    async def introspection_check(self, url: str) -> bool:
        query = {"query": "{ __schema { types { name } } }"}
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.post(url, json=query)
                if r.status_code == 200 and 'data' in r.json():
                    return True
            except Exception:
                return False
        return False

    async def test_injection(self, url: str, payload: str) -> Dict[str, Any]:
        # send payload as GraphQL query arg; simplistic
        query = {"query": f"query {{ test(arg: \"{payload}\") }}"}
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json=query)
            return {"status": r.status_code, "body": r.text}
