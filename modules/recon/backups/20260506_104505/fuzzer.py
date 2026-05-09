"""ffuf fuzzing engine - param/dir/value fuzzing"""
import asyncio, json, tempfile
from pathlib import Path
from core.runner import run_cmd, have, run_parallel
from core.logger import logger
from modules.recon.config.settings import FFUF_RATE, USER_AGENT

async def ffuf_param_fuzz(url, wordlist=None):
    """Fuzz hidden GET params"""
    if not have("ffuf"): return []
    wl = wordlist or "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    if not Path(wl).exists(): return []
    out = Path(tempfile.gettempdir()) / f"ffuf_{abs(hash(url))}.json"
    sep = "&" if "?" in url else "?"
    target = f"{url}{sep}FUZZ=test"
    cmd = (f'ffuf -u "{target}" -w {wl} -mc 200,500 -fs 0 '
           f'-rate {FFUF_RATE} -t 30 -of json -o {out} -s 2>/dev/null')
    await run_cmd(cmd, timeout=180)
    findings = []
    if out.exists():
        try:
            data = json.loads(out.read_text())
            for r in data.get("results", []):
                findings.append({"url": url, "param": r["input"]["FUZZ"], "status": r["status"]})
        except: pass
        out.unlink(missing_ok=True)
    return findings

async def ffuf_dir_fuzz(host, wordlist=None):
    """Directory bruteforce"""
    if not have("ffuf"): return []
    wl = wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"
    if not Path(wl).exists(): return []
    out = Path(tempfile.gettempdir()) / f"ffufd_{abs(hash(host))}.json"
    cmd = (f'ffuf -u "{host}/FUZZ" -w {wl} -mc 200,301,302,401,403 '
           f'-rate {FFUF_RATE} -t 30 -of json -o {out} -s 2>/dev/null')
    await run_cmd(cmd, timeout=240)
    findings = []
    if out.exists():
        try:
            data = json.loads(out.read_text())
            for r in data.get("results", []):
                findings.append({"host": host, "path": r["input"]["FUZZ"], "status": r["status"]})
        except: pass
        out.unlink(missing_ok=True)
    return findings

async def fuzz_all(hosts, param_urls, session):
    logger.info("⚡ FUZZING ENGINE")
    all_findings = {"params": [], "dirs": []}

    # Directory fuzz top hosts
    dir_tasks = [ffuf_dir_fuzz(h) for h in hosts[:5]]
    dr = await run_parallel(dir_tasks, max_concurrent=3)
    for r in dr:
        if isinstance(r, list):
            all_findings["dirs"].extend(r)

    # Param fuzz top URLs
    param_tasks = [ffuf_param_fuzz(u) for u in param_urls[:15]]
    pr = await run_parallel(param_tasks, max_concurrent=5)
    for r in pr:
        if isinstance(r, list):
            all_findings["params"].extend(r)

    logger.info(f"   ✓ Dirs found: {len(all_findings['dirs'])} | Hidden params: {len(all_findings['params'])}")
    session.update("fuzz_results", all_findings)
    return all_findings
