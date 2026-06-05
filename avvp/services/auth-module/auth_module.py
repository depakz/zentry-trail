import httpx
from typing import Optional, Dict, Any


async def get_authenticated_session(scan_id: str, credentials: Optional[Dict[str, Any]] = None) -> httpx.AsyncClient:
    """Return an authenticated httpx AsyncClient for the given scan.
    If `credentials` is None, this will return an unauthenticated client. In production,
    credentials should be read from Vault: secret/scans/{scan_id}/credentials
    """
    headers = {}
    cookies = None
    auth = None
    if credentials:
        if creds := credentials.get("bearer"):
            headers["Authorization"] = f"Bearer {creds}"
        if creds := credentials.get("api_key"):
            headers["X-API-KEY"] = creds
        if creds := credentials.get("cookies"):
            cookies = creds
        if creds := credentials.get("basic_auth"):
            auth = (creds.get("user"), creds.get("pass"))
    client = httpx.AsyncClient(headers=headers, auth=auth, cookies=cookies, timeout=30)
    return client
