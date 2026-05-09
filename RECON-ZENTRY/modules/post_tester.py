"""
POST / Parameter Fuzzing Engine
"""
import logging
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (HackWithYuva/3.0)"

PAYLOADS = [
    {"name": "sqli_basic", "value": "' OR 1=1-- -"},
    {"name": "sqli_quote", "value": "\""},
    {"name": "xss_basic", "value": "<script>alert(1)</script>"},
    {"name": "xss_img", "value": "\"><img src=x onerror=alert(1)>"},
    {"name": "fuzz_long", "value": "A" * 5000},
    {"name": "nullbyte", "value": "%00"},
    {"name": "cmd_inj", "value": ";id"},
]

ERROR_SIGNATURES = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL|sqlite_|Microsoft OLE DB|"
    r"Stack trace:|Traceback \(most recent|undefined index|fatal error|"
    r"unhandled exception)",
    re.I,
)


def extract_params(urls: List[str]) -> List[Dict]:
    """Extract URLs with query params."""
    params_list: List[Dict] = []
    seen = set()
    for u in urls:
        try:
            p = urlparse(u)
            if not p.query:
                continue
            qs = parse_qs(p.query, keep_blank_values=True)
            if not qs:
                continue
            base = f"{p.scheme}://{p.netloc}{p.path}"
            key = (base, tuple(sorted(qs.keys())))
            if key in seen:
                continue
            seen.add(key)
            params_list.append({"url": u, "base": base, "params": list(qs.keys())})
        except Exception:
            continue
    logger.info(f"[POST] Extracted {len(params_list)} parameterized URLs")
    return params_list


def _baseline(url: str, timeout: int = 8):
    try:
        return requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
    except Exception:
        return None


def _test_one(entry: Dict, timeout: int = 8) -> List[Dict]:
    findings: List[Dict] = []
    url = entry["url"]
    base = entry["base"]
    params = entry["params"]

    base_resp = _baseline(url, timeout)
    base_len = len(base_resp.text) if base_resp is not None else 0
    base_status = base_resp.status_code if base_resp is not None else 0

    for param in params:
        for payload in PAYLOADS:
            test_qs = {param: payload["value"]}
            test_url = f"{base}?{urlencode(test_qs)}"

            # GET test
            try:
                rg = requests.get(
                    test_url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
                if rg.status_code >= 500:
                    findings.append({
                        "url": test_url, "method": "GET",
                        "issue": "server_error_500",
                        "payload": payload["value"], "status": rg.status_code,
                    })
                if ERROR_SIGNATURES.search(rg.text):
                    findings.append({
                        "url": test_url, "method": "GET",
                        "issue": "error_signature_leak",
                        "payload": payload["value"], "status": rg.status_code,
                    })
                if payload["value"] in rg.text and "<script>" in payload["value"]:
                    findings.append({
                        "url": test_url, "method": "GET",
                        "issue": "possible_reflection_xss",
                        "payload": payload["value"], "status": rg.status_code,
                    })
            except Exception as e:
                logger.debug(f"[POST] GET err {test_url}: {e}")

            # POST JSON test
            try:
                rp = requests.post(
                    base,
                    json={param: payload["value"]},
                    headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
                if rp.status_code >= 500:
                    findings.append({
                        "url": base, "method": "POST_JSON",
                        "issue": "server_error_500",
                        "payload": payload["value"], "status": rp.status_code,
                    })
                if ERROR_SIGNATURES.search(rp.text):
                    findings.append({
                        "url": base, "method": "POST_JSON",
                        "issue": "error_signature_leak",
                        "payload": payload["value"], "status": rp.status_code,
                    })
            except Exception as e:
                logger.debug(f"[POST] POST err {base}: {e}")

    return findings


def run_post_tests(param_entries: List[Dict], threads: int = 15, timeout: int = 8) -> List[Dict]:
    """Run fuzz/POST tests against parameterized URLs."""
    if not param_entries:
        return []

    requests.packages.urllib3.disable_warnings()

    # Cap to prevent absurd test counts
    if len(param_entries) > 500:
        logger.warning(f"[POST] Capping {len(param_entries)} to 500 entries")
        param_entries = param_entries[:500]

    all_findings: List[Dict] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_test_one, e, timeout): e for e in param_entries}
        for fut in as_completed(futures):
            try:
                all_findings.extend(fut.result())
            except Exception:
                continue

    logger.info(f"[POST] Total findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    p = extract_params(["https://example.com/a?id=1", "https://example.com/b?q=test"])
    print(run_post_tests(p))
