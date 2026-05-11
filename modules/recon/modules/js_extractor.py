"""
JS Endpoint Extractor - Pull endpoints from JS files
"""
import re
import logging
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)
from core.logger import dashboard

USER_AGENT = "Mozilla/5.0 (HackWithYuva/3.0)"

# Endpoint regexes
ENDPOINT_PATTERNS = [
    re.compile(r"""['"`]((?:/|https?://)[a-zA-Z0-9_\-./?=&%~+:]{2,200})['"`]"""),
    re.compile(r"""['"`](/(?:api|v\d+|graphql|auth|rest|admin|user|users|account|login|oauth)[a-zA-Z0-9_\-./?=&%~+:]{0,200})['"`]"""),
]

API_HINTS = re.compile(r"/(api|v\d+|graphql|auth|rest|oauth|admin|internal)/", re.I)


def _filter_js(urls: List[str]) -> List[str]:
    js_files: Set[str] = set()
    for u in urls:
        try:
            path = urlparse(u).path.lower()
            if path.endswith(".js") or ".js?" in u.lower():
                js_files.add(u)
        except Exception:
            continue
    return sorted(js_files)


def _fetch(url: str, timeout: int = 10) -> str:
    try:
        r = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        if r.status_code == 200 and len(r.text) < 5_000_000:
            return r.text
    except Exception as e:
        logger.debug(f"[JS] fetch error {url}: {e}")
    return ""


def _extract_from_content(content: str, base_url: str) -> Set[str]:
    found: Set[str] = set()
    for pat in ENDPOINT_PATTERNS:
        for m in pat.findall(content):
            ep = m.strip()
            if not ep or len(ep) < 2:
                continue
            if ep.startswith(("http://", "https://")):
                found.add(ep)
            elif ep.startswith("/"):
                try:
                    found.add(urljoin(base_url, ep))
                except Exception:
                    pass
    return found


def extract_js_endpoints(urls: List[str], threads: int = 20, timeout: int = 10) -> Dict[str, List[str]]:
    """
    Extract endpoints from JS files.
    Returns: {"js_files": [...], "endpoints": [...]}
    """
    if not urls:
        return {"js_files": [], "endpoints": []}

    requests.packages.urllib3.disable_warnings()

    js_files = _filter_js(urls)
    logger.info(f"[JS] Found {len(js_files)} JS files to analyze")
    try:
        dashboard.advance_recon(f"js:files:{len(js_files)}")
    except Exception:
        pass

    all_endpoints: Set[str] = set()

    if not js_files:
        return {"js_files": [], "endpoints": []}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_map = {ex.submit(_fetch, j, timeout): j for j in js_files}
        for fut in as_completed(future_map):
            js_url = future_map[fut]
            try:
                content = fut.result()
                if not content:
                    continue
                found = _extract_from_content(content, js_url)
                all_endpoints.update(found)
            except Exception as e:
                logger.debug(f"[JS] error {js_url}: {e}")

    endpoints = sorted(all_endpoints)
    api_eps = [e for e in endpoints if API_HINTS.search(e)]
    logger.info(f"[JS] Extracted {len(endpoints)} endpoints ({len(api_eps)} API-like)")
    try:
        dashboard.advance_recon(f"js:endpoints:{len(endpoints)}")
    except Exception:
        pass

    return {"js_files": js_files, "endpoints": endpoints}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(extract_js_endpoints(["https://example.com/main.js"]))
