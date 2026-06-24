"""Recon Parsers: JS endpoint extraction and parameter mining."""

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger("zentry.recon.parsers")
log = logger

USER_AGENT = "Mozilla/5.0 (HackWithYuva/3.0)"


# =========================================================================
# JS Endpoint Extractor
# =========================================================================

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

    return {"js_files": js_files, "endpoints": endpoints}


# =========================================================================
# Precision Parameter Miner
# =========================================================================

_SKIP_EXT = ('.html','.htm','.json','.js','.css','.png','.jpg','.jpeg','.gif',
             '.ico','.svg','.woff','.woff2','.ttf','.eot','.axd','.pdf','.zip',
             '.xml','.txt','.map','.mp4','.webp','.mp3','.avi')
_SKIP_PATHS = ('/.well-known/','/images/','/static/','/assets/','/img/',
               '/css/','/js/','/fonts/','/media/','captchaimage',
               'webresource.axd','scriptresource.axd')
_DYNAMIC_EXT = ('.php','.aspx','.asp','.jsp','.do','.action','.cgi','.pl','.py')

def _should_mine(url: str) -> bool:
    try:
        u = url.lower()
        path = urlparse(u).path
        if path.endswith(_SKIP_EXT):
            return False
        if any(p in u for p in _SKIP_PATHS):
            return False
        return True
    except Exception:
        return False

def _is_dynamic(url: str) -> bool:
    """Higher priority for dynamic URLs."""
    try:
        path = urlparse(url.lower()).path
        return path.endswith(_DYNAMIC_EXT) or '?' in url
    except Exception:
        return False

def _extract_params_from_urls(urls):
    """Fastest method: parse params already present in discovered URLs."""
    param_map = {}
    for url in urls:
        try:
            qs = urlparse(url).query
            if not qs:
                continue
            params = list(parse_qs(qs).keys())
            if params:
                base = url.split('?')[0]
                param_map.setdefault(base, set()).update(params)
        except Exception:
            continue
    return {k: list(v) for k, v in param_map.items()}

async def _run_arjun(url, sem, timeout=40):
    if not shutil.which("arjun"):
        return url, []
    async with sem:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                          delete=False, prefix='arjun_')
        tmp.close()
        try:
            cmd = ["arjun", "-u", url, "-oJ", tmp.name,
                   "-t", "10", "--stable", "-T", "5"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                log.debug(f"   ⏱️  arjun timeout: {url[:70]}")
                try: proc.kill(); await proc.wait()
                except Exception: pass
                return url, []

            if os.path.exists(tmp.name) and os.path.getsize(tmp.name) > 0:
                try:
                    data = json.load(open(tmp.name))
                    params = []
                    if isinstance(data, dict):
                        for v in data.values():
                            if isinstance(v, dict) and 'params' in v:
                                params.extend(v['params'])
                            elif isinstance(v, list):
                                params.extend(v)
                    elif isinstance(data, list):
                         params = data
                    return url, list(set(params))
                except Exception:
                    return url, []
            return url, []
        finally:
            try: os.unlink(tmp.name)
            except Exception: pass

async def _run_paramspider(domain, timeout=60):
    if not shutil.which("paramspider"):
        return []
    out_dir = tempfile.mkdtemp(prefix="psp_")
    try:
        cmd = ["paramspider", "-d", domain, "-o", out_dir]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill(); await proc.wait()
            except Exception: pass
            return []
        urls = []
        for root, _, files in os.walk(out_dir):
            for fn in files:
                try:
                    with open(os.path.join(root, fn)) as f:
                        urls += f.read().splitlines()
                except Exception: pass
        return [u for u in urls if u.strip()]
    finally:
        try: shutil.rmtree(out_dir)
        except Exception: pass

async def mine_parameters(hosts, endpoints, session,
                          max_arjun=8, concurrency=4):
    """
    Precision parameter mining.
    Returns: (extra_urls, param_map)
    """
    log.info("🔎 PARAMETER MINING (precision)")
    if os.environ.get("YUVA_SKIP_PARAMS") == "1":
        log.info("   └─ YUVA_SKIP_PARAMS=1, skipping")
        return [], {}

    extra_urls = []
    params = {}

    regex_params = _extract_params_from_urls(endpoints)
    if regex_params:
        log.info(f"   ├─ Regex extracted: {sum(len(v) for v in regex_params.values())} "
                 f"params across {len(regex_params)} URLs")
        params.update(regex_params)
        for url, plist in regex_params.items():
            for p in plist:
                sep = '&' if '?' in url else '?'
                extra_urls.append(f"{url}{sep}{p}=FUZZ")

    for host in hosts[:2]:
        try:
            psp = await _run_paramspider(host, timeout=45)
            if psp:
                log.info(f"   ├─ paramspider({host}): {len(psp)} URLs")
                more = _extract_params_from_urls(psp)
                for k, v in more.items():
                    params.setdefault(k, []).extend(v)
                    params[k] = list(set(params[k]))
                extra_urls.extend(psp[:200])
        except Exception as e:
            log.debug(f"paramspider error: {e}")

    if shutil.which("arjun"):
        candidates = [u for u in endpoints if _should_mine(u)]
        candidates.sort(key=lambda u: (not _is_dynamic(u), len(u)))
        candidates = candidates[:max_arjun]

        if candidates:
            log.info(f"   ├─ arjun candidates: {len(candidates)} (dynamic prioritized)")
            sem = asyncio.Semaphore(concurrency)
            tasks = [_run_arjun(u, sem) for u in candidates]
            done = 0
            for coro in asyncio.as_completed(tasks):
                url, found = await coro
                done += 1
                if found:
                    params.setdefault(url, []).extend(found)
                    params[url] = list(set(params[url]))
                    for p in found:
                        sep = '&' if '?' in url else '?'
                        extra_urls.append(f"{url}{sep}{p}=FUZZ")
                    log.info(f"   │  [{done}/{len(candidates)}] ✓ "
                             f"{url[:55]} +{len(found)}")
    else:
        log.warning("   ├─ arjun not installed")

    total_params = sum(len(v) for v in params.values())
    log.info(f"   └─ Total: {total_params} params / {len(params)} URLs "
             f"/ +{len(extra_urls)} fuzz URLs")

    try:
        session.update("mined_params", params)
    except Exception:
        pass

    return list(set(extra_urls)), params
