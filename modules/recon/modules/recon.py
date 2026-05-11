"""Subdomain recon: subfinder + crt.sh + amass with fallbacks"""
import subprocess
import requests
import shutil
import sys
from pathlib import Path
from core.logger import logger, dashboard


def run_subfinder(domain):
    if not shutil.which("subfinder"):
        logger.warning("⚠️  subfinder not found in PATH")
        return []
    try:
        r = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode == 0:
            subs = [s.strip() for s in r.stdout.splitlines() if s.strip()]
            if subs:
                logger.info(f"   ✓ subfinder ({len(subs)} results)")
            return subs
        else:
            logger.warning(f"subfinder returned error code {r.returncode}")
            return []
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  subfinder timeout (300s)")
        return []
    except Exception as e:
        logger.error(f"subfinder error: {e}")
        return []


def run_crtsh(domain):
    """Query certificate transparency logs"""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=30, verify=False)
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data:
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n and n.endswith(domain):
                        subs.add(n)
            if subs:
                logger.info(f"   ✓ crt.sh ({len(subs)} results)")
            return list(subs)
        else:
            logger.warning(f"crt.sh returned status {r.status_code}")
    except requests.Timeout:
        logger.warning(f"⏱️  crt.sh timeout")
    except Exception as e:
        logger.warning(f"crt.sh error: {e}")
    return []


def run_amass(domain):
    """Fallback to amass if available"""
    if not shutil.which("amass"):
        return []
    try:
        r = subprocess.run(
            ["amass", "enum", "-d", domain, "-passive"],
            capture_output=True, text=True, timeout=180
        )
        if r.returncode == 0:
            subs = [s.strip() for s in r.stdout.splitlines() if s.strip()]
            if subs:
                logger.info(f"   ✓ amass ({len(subs)} results)")
            return subs
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  amass timeout")
    except Exception as e:
        logger.debug(f"amass unavailable: {e}")
    return []


def run_recon(domain, fast=True):
    logger.info(f"🔍 RECON: {domain}")
    all_subs = set([domain])

    # initialize recon progress based on runner files in modules/recon/recon/
    try:
        recon_dir = Path(__file__).resolve().parents[1] / "recon"
        modules_dir = Path(__file__).resolve().parents[0]
        tool_files = [p for p in recon_dir.iterdir() if p.is_file() and p.suffix == ".py" and p.name.endswith("_runner.py")]
        module_runners = [p for p in modules_dir.iterdir() if p.is_file() and p.suffix == ".py" and (p.name.endswith("_runner.py") or any(tok in p.name for tok in ("gau", "nuclei", "probe", "discovery")))]
        total = max(1, len(tool_files) + len(module_runners))
        dashboard.init_recon(total)
    except Exception:
        dashboard.init_recon(3)

    # Try all sources and advance the shared recon progress after each tool completes
    all_subs.update(run_subfinder(domain))
    try:
        dashboard.advance_recon("subfinder done")
    except Exception:
        pass

    all_subs.update(run_crtsh(domain))
    try:
        dashboard.advance_recon("crt.sh done")
    except Exception:
        pass

    if not fast:
        all_subs.update(run_amass(domain))
        try:
            dashboard.advance_recon("amass done")
        except Exception:
            pass

    subs = sorted(all_subs)
    logger.info(f"   → {len(subs)} unique subdomains found")

    if len(subs) == 1:
        logger.warning("⚠️  Only found base domain - consider checking your internet or DNS")

    return subs
