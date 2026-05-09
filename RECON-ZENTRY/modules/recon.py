"""Subdomain recon: subfinder + crt.sh"""
import subprocess, requests, shutil
from core.logger import logger

def run_subfinder(domain):
    if not shutil.which("subfinder"):
        logger.warning("subfinder not found")
        return []
    try:
        r = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=300
        )
        subs = [s.strip() for s in r.stdout.splitlines() if s.strip()]
        logger.info(f"   ✓ subfinder ({len(subs)} results)")
        return subs
    except Exception as e:
        logger.error(f"subfinder error: {e}")
        return []

def run_crtsh(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data:
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith(domain):
                        subs.add(n)
            logger.info(f"   ✓ crt.sh ({len(subs)} results)")
            return list(subs)
    except Exception as e:
        logger.warning(f"crt.sh error: {e}")
    return []

def run_recon(domain, fast=True):
    logger.info(f"🔍 RECON: {domain}")
    all_subs = set([domain])
    all_subs.update(run_subfinder(domain))
    all_subs.update(run_crtsh(domain))
    subs = sorted(all_subs)
    logger.info(f"   → {len(subs)} unique subdomains")
    return subs
