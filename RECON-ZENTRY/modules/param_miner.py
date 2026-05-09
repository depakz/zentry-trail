"""
param_miner.py — YUVA Precision Edition
Fallback chain: regex extraction → arjun (smart) → paramspider
Guarantees baseline parameter detection even when network is hostile.
"""
import asyncio, json, logging, os, re, shutil, tempfile
from urllib.parse import urlparse, parse_qs

log = logging.getLogger(__name__)

# ---------- Filtering ----------
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

# ---------- Strategy 1: Regex extraction from existing URLs ----------
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

# ---------- Strategy 2: Arjun (controlled) ----------
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

# ---------- Strategy 3: Paramspider ----------
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
                    urls += open(os.path.join(root, fn)).read().splitlines()
                except Exception: pass
        return [u for u in urls if u.strip()]
    finally:
        try: shutil.rmtree(out_dir)
        except Exception: pass

# ---------- Public API ----------
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

    # ----- Strategy 1: regex extraction (always, free) -----
    regex_params = _extract_params_from_urls(endpoints)
    if regex_params:
        log.info(f"   ├─ Regex extracted: {sum(len(v) for v in regex_params.values())} "
                 f"params across {len(regex_params)} URLs")
        params.update(regex_params)
        for url, plist in regex_params.items():
            for p in plist:
                sep = '&' if '?' in url else '?'
                extra_urls.append(f"{url}{sep}{p}=FUZZ")

    # ----- Strategy 2: paramspider (fast, passive) -----
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

    # ----- Strategy 3: arjun (only on best candidates) -----
    if shutil.which("arjun"):
        # Prioritize dynamic URLs
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

    try: session.update("mined_params", params)
    except Exception: pass

    return list(set(extra_urls)), params
