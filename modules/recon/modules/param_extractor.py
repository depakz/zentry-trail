"""
param_extractor.py — Query/POST/JSON parameter extractor
Hack With Yuva v3.0
"""

import re
import json
import logging
import subprocess
import shutil
from typing import List, Dict, Set
from urllib.parse import urlparse, parse_qs

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger("HWY.param_extractor")
from core.logger import dashboard

PARAM_KEY_RE    = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)=")
JSON_KEY_RE     = re.compile(r'"([a-zA-Z_][a-zA-Z0-9_]{1,40})"\s*:')
POST_FIELD_RE   = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
INPUT_NAME_RE   = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)
TEXTAREA_RE     = re.compile(r'<textarea[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)


# ──────────────────────────────────────────────
# URL query params
# ──────────────────────────────────────────────

def extract_query_params(urls: List[str]) -> Dict[str, List[str]]:
    """
    From a list of URLs, extract {url: [param, ...]} for URLs that have query params.
    """
    result: Dict[str, List[str]] = {}
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        keys = list(parse_qs(parsed.query).keys())
        if keys:
            result[url] = keys
    logger.info("[PARAM] %d parameterized URLs from %d total", len(result), len(urls))
    try:
        dashboard.advance_recon(f"param:query:{len(result)}")
    except Exception:
        pass
    return result


# ──────────────────────────────────────────────
# Regex fallback — scan raw content
# ──────────────────────────────────────────────

def extract_params_from_content(content: str) -> Dict:
    """Extract all param-like tokens from raw HTML/JS/JSON content."""
    return {
        "query_params":  list(dict.fromkeys(PARAM_KEY_RE.findall(content))),
        "json_keys":     list(dict.fromkeys(JSON_KEY_RE.findall(content))),
        "form_fields":   list(dict.fromkeys(
            POST_FIELD_RE.findall(content)
            + INPUT_NAME_RE.findall(content)
            + TEXTAREA_RE.findall(content)
        )),
    }


# ──────────────────────────────────────────────
# Arjun integration (optional)
# ──────────────────────────────────────────────

def _arjun_available() -> bool:
    return shutil.which("arjun") is not None


def run_arjun(url: str, timeout: int = 90) -> List[str]:
    """
    Run arjun to discover hidden parameters for a single URL.
    Returns list of discovered param names, [] on failure.
    """
    if not _arjun_available():
        logger.debug("[PARAM] arjun not found — skipping.")
        return []
    try:
        cmd = ["arjun", "-u", url, "--stable", "-q", "-oJ", "/tmp/arjun_out.json"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        try:
            with open("/tmp/arjun_out.json") as f:
                data = json.load(f)
            params = data.get("params", [])
            logger.info("[PARAM] arjun found %d params for %s", len(params), url)
            return params
        except Exception:
            return []
    except subprocess.TimeoutExpired:
        logger.warning("[PARAM] arjun timed out for %s", url)
        return []
    except Exception as exc:
        logger.warning("[PARAM] arjun error: %s", exc)
        return []


def run_arjun_batch(urls: List[str], max_urls: int = 20) -> Dict[str, List[str]]:
    """Run arjun on up to max_urls prioritized endpoints."""
    result: Dict[str, List[str]] = {}
    for url in urls[:max_urls]:
        params = run_arjun(url)
        if params:
            result[url] = params
    return result


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def extract_all_params(
    urls: List[str],
    js_param_keys: List[str] | None = None,
    run_arjun_flag: bool = False,
) -> Dict:
    """
    Master parameter extraction:
      - URL query params
      - JS-parsed keys
      - Arjun (optional)

    Returns:
        {
          "parameterized_urls": {url: [params]},
          "all_param_keys": [...],
          "arjun_results": {url: [params]}   # if enabled
        }
    """
    js_param_keys = js_param_keys or []

    parameterized = extract_query_params(urls)
    all_keys: Set[str] = set(js_param_keys)
    for param_list in parameterized.values():
        all_keys.update(param_list)

    arjun_results: Dict[str, List[str]] = {}
    if run_arjun_flag and _arjun_available():
        # Prioritize parameterized URLs + API endpoints
        priority = [u for u in urls if u in parameterized]
        arjun_results = run_arjun_batch(priority, max_urls=15)
        for url, params in arjun_results.items():
            all_keys.update(params)

    logger.info(
        "[PARAM] Summary — %d param URLs, %d unique keys, %d arjun hits",
        len(parameterized), len(all_keys), len(arjun_results),
    )
    try:
        dashboard.advance_recon(f"param:summary:urls{len(parameterized)}:keys{len(all_keys)}")
    except Exception:
        pass
    return {
        "parameterized_urls": parameterized,
        "all_param_keys":     sorted(all_keys),
        "arjun_results":      arjun_results,
    }
