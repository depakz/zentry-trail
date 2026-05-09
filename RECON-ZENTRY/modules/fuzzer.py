"""
fuzzer.py — YUVA Precision Edition
Adds baseline validation to filter ffuf noise.
- Captures baseline length/status before fuzzing
- Filters results matching baseline (boring)
- Auto-calibration via ffuf -ac
"""
import asyncio, json, logging, os, shutil, tempfile, statistics
import requests
from urllib.parse import urlparse

log = logging.getLogger(__name__)

DIR_WORDLIST  = os.environ.get("YUVA_DIR_WL",
    "/usr/share/seclists/Discovery/Web-Content/common.txt")
PARAM_WORDLIST = os.environ.get("YUVA_PARAM_WL",
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt")

# ---------- Baseline ----------
def _baseline(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=False,
                         headers={'User-Agent':'Mozilla/5.0 YUVA'})
        return {
            "status": r.status_code,
            "length": len(r.content),
            "words":  len(r.text.split()),
            "lines":  r.text.count('\n')
        }
    except Exception:
        return None

# ---------- ffuf runner ----------
async def _run_ffuf(url, wordlist, mode="dir", timeout=240):
    if not shutil.which("ffuf"):
        log.warning("ffuf not found")
        return []
    if not os.path.exists(wordlist):
        log.warning(f"wordlist missing: {wordlist}")
        return []

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                      delete=False, prefix='ffuf_')
    tmp.close()

    if mode == "dir":
        target = url.rstrip('/') + "/FUZZ"
    else:
        sep = '&' if '?' in url else '?'
        target = f"{url}{sep}FUZZ=test"

    cmd = ["ffuf", "-u", target, "-w", wordlist,
           "-mc", "200,201,204,301,302,307,401,403,500",
           "-fc", "404",
           "-ac",                # auto-calibration
           "-t", "40",
           "-rate", "60",
           "-timeout", "8",
           "-of", "json", "-o", tmp.name,
           "-s"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill(); await proc.wait()
            except Exception: pass

        if not os.path.exists(tmp.name) or os.path.getsize(tmp.name) == 0:
            return []
        try:
            data = json.load(open(tmp.name))
        except Exception:
            return []
        return data.get("results", []) or []
    finally:
        try: os.unlink(tmp.name)
        except Exception: pass

# ---------- Validation ----------
def _validate(results, baseline):
    """
    Filter ffuf results against baseline.
    Keep only results that meaningfully differ.
    """
    if not results:
        return []
    if not baseline:
        return results  # no baseline → keep all

    # Compute mode length from results
    lengths = [r.get("length", 0) for r in results]
    common_len = None
    if lengths:
        try:
            common_len = statistics.mode(lengths)
        except statistics.StatisticsError:
            common_len = None

    keep = []
    for r in results:
        st = r.get("status", 0)
        ln = r.get("length", 0)

        # Skip if matches baseline exactly
        if st == baseline["status"] and abs(ln - baseline["length"]) < 30:
            continue
        # Skip if matches noise mode
        if common_len and abs(ln - common_len) < 10 and st in (200, 403):
            continue
        # Keep interesting status codes
        if st in (200, 301, 302, 401, 403, 500):
            keep.append(r)
    return keep

# ---------- Public API ----------
async def fuzz_all(alive_hosts, top_urls, session):
    log.info("⚡ FUZZING ENGINE (validated)")

    if os.environ.get("YUVA_SKIP_FUZZ") == "1":
        log.info("   └─ YUVA_SKIP_FUZZ=1, skipping")
        return {"dirs": [], "params": []}

    all_dirs   = []
    all_params = []

    # ----- Directory fuzzing on alive hosts -----
    for host in alive_hosts[:3]:
        baseline = _baseline(host.rstrip('/') + "/__yuva_baseline_xyz")
        log.info(f"   ├─ dir fuzz: {host} (baseline {baseline})")
        raw = await _run_ffuf(host, DIR_WORDLIST, mode="dir")
        validated = _validate(raw, baseline)
        log.info(f"   │  raw={len(raw)} → validated={len(validated)}")
        for r in validated:
            r["_source"] = host
            all_dirs.append(r)

    # ----- Param fuzzing on top dynamic URLs -----
    dyn_urls = [u for u in top_urls if any(
        urlparse(u).path.lower().endswith(e)
        for e in ('.php','.aspx','.asp','.jsp','.do','.action'))][:5]

    for url in dyn_urls:
        baseline = _baseline(url)
        log.info(f"   ├─ param fuzz: {url[:60]}")
        raw = await _run_ffuf(url, PARAM_WORDLIST, mode="param", timeout=180)
        validated = _validate(raw, baseline)
        log.info(f"   │  raw={len(raw)} → validated={len(validated)}")
        for r in validated:
            r["_source"] = url
            all_params.append(r)

    log.info(f"   └─ Validated: dirs={len(all_dirs)}  params={len(all_params)}")
    try:
        session.update("fuzz_dirs", all_dirs)
        session.update("fuzz_params", all_params)
    except Exception: pass
    return {"dirs": all_dirs, "params": all_params}
