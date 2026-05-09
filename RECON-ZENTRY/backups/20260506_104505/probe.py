"""Alive host probing with httpx"""
import subprocess, json, tempfile, shutil
from pathlib import Path
from core.logger import logger

def run_probe(subdomains):
    if not shutil.which("httpx"):
        logger.warning("httpx not found, returning all subs as alive")
        return [f"http://{s}" for s in subdomains]

    if not subdomains: return []
    inp = Path(tempfile.gettempdir()) / "httpx_in.txt"
    inp.write_text("\n".join(subdomains))

    logger.info(f"🌐 PROBING {len(subdomains)} hosts with httpx")
    try:
        r = subprocess.run(
            ["httpx", "-l", str(inp), "-json", "-silent",
             "-status-code", "-timeout", "10", "-threads", "50",
             "-retries", "1", "-follow-redirects"],
            capture_output=True, text=True, timeout=600
        )
        alive = []
        for line in r.stdout.splitlines():
            try:
                d = json.loads(line)
                url = d.get("url")
                if url: alive.append(url)
            except: pass
        inp.unlink(missing_ok=True)
        logger.info(f"   ✓ httpx ({len(alive)} alive)")
        for u in alive[:5]:
            logger.info(f"      • {u}")
        return alive
    except Exception as e:
        logger.error(f"httpx error: {e}")
        return []
