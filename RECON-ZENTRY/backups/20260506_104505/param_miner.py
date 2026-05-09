"""
param_miner.py — YUVA optimized
- Pre-filters URLs (skips static/images/.html/.json/.axd)
- Caps URLs to mine (default 20)
- Short timeout (45s) + 1 retry
- Concurrent execution (5 workers)
"""
import asyncio
import json
import logging
import os
import shutil
import tempfile
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# ---------- URL filter ----------
_SKIP_EXT = ('.html', '.htm', '.json', '.js', '.css', '.png', '.jpg', '.jpeg',
             '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
             '.axd', '.pdf', '.zip', '.xml', '.txt', '.map', '.mp4', '.webp')
_SKIP_PATHS = ('/.well-known/', '/images/', '/static/', '/assets/',
               '/img/', '/css/', '/js/', '/fonts/', '/media/',
               'captchaimage', 'webresource.axd', 'scriptresource.axd')

def _should_mine(url: str) -> bool:
    try:
        u = url.lower()
        path = urlparse(u).path
        if path.endswith(_SKIP_EXT):
            return False
        if any(p in u for p in _SKIP_PATHS):
            return False
        # Skip URLs with random-looking hash filenames
        if path.count('/') > 6:
            return False
        return True
    except Exception:
        return False


# ---------- Arjun runner ----------
async def _run_arjun(url: str, sem: asyncio.Semaphore,
                     timeout: int = 45, retries: int = 1):
    """Run arjun once on a URL with short timeout."""
    if not shutil.which("arjun"):
        return url, []

    async with sem:
        for attempt in range(retries):
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False, prefix='arjun_')
            tmp.close()
            try:
                cmd = [
                    "arjun", "-u", url, "-oJ", tmp.name,
                    "-t", "10",       # 10 threads
                    "--stable",
                    "-T", "5",        # request timeout 5s
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    log.warning(f"⏱️  TIMEOUT (attempt {attempt+1}): arjun {url[:80]}")
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
                    continue

                # parse output
                if os.path.exists(tmp.name) and os.path.getsize(tmp.name) > 0:
                    try:
                        with open(tmp.name) as f:
                            data = json.load(f)
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
                    except Exception as e:
                        log.debug(f"arjun parse error for {url}: {e}")
                return url, []
            finally:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass
    return url, []


# ---------- Public API ----------
async def mine_parameters(hosts, endpoints, session,
                          max_urls: int = 20, concurrency: int = 5):
    """
    Mine parameters from a filtered subset of endpoints.
    Returns: (extra_urls, param_dict)
    """
    log.info("🔎 PARAMETER MINING (optimized)")
    # Skip if user requested
    if os.environ.get("YUVA_SKIP_ARJUN") == "1":
        log.info("   └─ YUVA_SKIP_ARJUN=1 set, skipping arjun")
        return [], {}


    # Filter endpoints
    candidates = [u for u in endpoints if _should_mine(u)]
    log.info(f"   ├─ Filtered: {len(endpoints)} → {len(candidates)} URLs")

    # Cap
    if len(candidates) > max_urls:
        candidates = candidates[:max_urls]
        log.info(f"   ├─ Capped to first {max_urls} URLs")

    if not candidates:
        log.info("   └─ No URLs eligible for param mining, skipping")
        return [], {}

    # paramspider check
    if not shutil.which("paramspider"):
        log.warning("   ├─ paramspider not found, skipping")
    if not shutil.which("arjun"):
        log.warning("   └─ arjun not found, skipping param mining entirely")
        return [], {}

    # Run arjun concurrently
    sem = asyncio.Semaphore(concurrency)
    tasks = [_run_arjun(url, sem) for url in candidates]

    extra_urls = []
    params = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        url, found = await coro
        done += 1
        if found:
            params[url] = found
            for p in found:
                sep = '&' if '?' in url else '?'
                extra_urls.append(f"{url}{sep}{p}=FUZZ")
            log.info(f"   [{done}/{len(candidates)}] ✓ {url[:60]} → {len(found)} params")
        else:
            log.debug(f"   [{done}/{len(candidates)}] - {url[:60]}")

    log.info(f"   └─ Discovered {sum(len(v) for v in params.values())} params "
             f"across {len(params)} URLs → +{len(extra_urls)} URLs")

    try:
        session.update("mined_params", params)
    except Exception:
        pass

    return extra_urls, params
