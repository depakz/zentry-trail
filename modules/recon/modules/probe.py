"""Alive host probing with httpx + fallback"""
import subprocess
import json
import tempfile
import shutil
from pathlib import Path
from core.logger import logger
from core.logger import dashboard


def run_probe(subdomains):
    if not shutil.which("httpx"):
        logger.warning("⚠️  httpx not found, returning all subs as potentially alive")
        return [f"http://{s}" for s in subdomains]

    if not subdomains:
        return []
    
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
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                url = d.get("url")
                status = d.get("status_code", 0)
                if url and 200 <= status < 500:
                    alive.append(url)
            except json.JSONDecodeError:
                pass
        
        inp.unlink(missing_ok=True)
        
        if alive:
            logger.info(f"   ✓ httpx ({len(alive)} alive)")
            for u in alive[:5]:
                logger.info(f"      • {u}")
            try:
                dashboard.advance_recon(f"httpx:{len(alive)}")
            except Exception:
                pass
        else:
            logger.warning(f"   ⚠️  httpx found no alive hosts (tested {len(subdomains)})")
        
        return alive
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  httpx timeout (600s)")
        inp.unlink(missing_ok=True)
        return []
    except Exception as e:
        logger.error(f"httpx error: {e}")
        inp.unlink(missing_ok=True)
        # Fallback: try with basic http
        return [f"http://{s}" for s in subdomains[:10]]
