"""
API Discovery Engine
"""
import logging
import re
from typing import List, Dict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (HackWithYuva/3.0)"

API_PATH_RE = re.compile(r"/(api|v\d+|rest|service|services)/", re.I)
GRAPHQL_RE = re.compile(r"/(graphql|gql)(/|$|\?)", re.I)
AUTH_RE = re.compile(r"/(auth|login|oauth|token|signin|sign-in|sso|register|signup)(/|$|\?)", re.I)


def _classify(url: str, content_type: str = "") -> str:
    if GRAPHQL_RE.search(url):
        return "GRAPHQL"
    if AUTH_RE.search(url):
        return "AUTH"
    if API_PATH_RE.search(url):
        return "REST"
    if "application/json" in content_type.lower():
        return "REST"
    return ""


def _probe(url: str, timeout: int = 8) -> Dict:
    try:
        r = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        ctype = r.headers.get("Content-Type", "")
        api_type = _classify(url, ctype)
        if api_type:
            return {
                "url": url,
                "type": api_type,
                "method": "GET",
                "status": r.status_code,
                "content_type": ctype.split(";")[0].strip(),
            }
    except Exception as e:
        logger.debug(f"[API] probe err {url}: {e}")
    return {}


def discover_apis(urls: List[str], threads: int = 30, timeout: int = 8) -> List[Dict]:
    """Discover and classify API endpoints."""
    if not urls:
        return []

    requests.packages.urllib3.disable_warnings()

    # Fast pre-filter on path
    candidates = []
    for u in urls:
        try:
            if API_PATH_RE.search(u) or GRAPHQL_RE.search(u) or AUTH_RE.search(u):
                candidates.append(u)
        except Exception:
            continue

    # dedupe
    candidates = list(dict.fromkeys(candidates))
    logger.info(f"[API] {len(candidates)} candidate API URLs from {len(urls)} input")

    findings: List[Dict] = []
    if not candidates:
        return []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe, c, timeout): c for c in candidates}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    findings.append(res)
            except Exception:
                continue

    logger.info(f"[API] Confirmed {len(findings)} API endpoints")
    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(discover_apis(["https://example.com/api/v1/users"]))
