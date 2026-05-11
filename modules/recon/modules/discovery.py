"""Endpoint discovery: katana + gau with intelligent fallbacks"""
import subprocess
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from core.logger import logger
from core.logger import dashboard


def run_katana(url, depth=2):
    if not shutil.which("katana"):
        logger.debug("katana not available")
        return []
    try:
        r = subprocess.run(
            ["katana", "-u", url, "-silent", "-d", str(depth),
             "-jc", "-kf", "all", "-c", "10", "-timeout", "10",
             "-rl", "100"],
            capture_output=True, text=True, timeout=120
        )
        if r.returncode == 0:
            urls = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
            if urls:
                logger.info(f"      └─ katana: {len(urls)} URLs")
            return urls
        else:
            logger.debug(f"katana returned code {r.returncode}")
            return []
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  katana timeout for {url}")
        return []
    except Exception as e:
        logger.debug(f"katana error: {e}")
        return []


def run_gau(domain):
    if not shutil.which("gau"):
        logger.debug("gau not available")
        return []
    try:
        r = subprocess.run(
            ["gau", "--threads", "3", "--timeout", "15", domain],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode == 0:
            urls = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
            if urls:
                logger.info(f"      └─ gau: {len(urls)} URLs")
            return urls
        else:
            logger.debug(f"gau returned code {r.returncode}")
            return []
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  gau timeout for {domain}")
        return []
    except Exception as e:
        logger.debug(f"gau error: {e}")
        return []


def run_gospider(url):
    """Fallback: gospider crawler"""
    if not shutil.which("gospider"):
        return []
    try:
        r = subprocess.run(
            ["gospider", "-s", url, "-c", "3", "-d", "2", "-t", "3"],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode == 0:
            urls = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
            if urls:
                logger.info(f"      └─ gospider: {len(urls)} URLs")
            return urls
    except Exception:
        pass
    return []


def filter_urls(urls):
    """Remove static junk and deduplicate"""
    skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
                ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".exe", ".dll", ".zip",
                ".tar", ".gz", ".pdf", ".doc", ".docx")
    out = []
    seen = set()
    for u in urls:
        if not isinstance(u, str) or not u.strip():
            continue
        if u.lower().endswith(skip_ext):
            continue
        # Dedupe by path+param-keys
        try:
            p = urlparse(u)
            key = (p.netloc, p.path, tuple(sorted([x.split('=')[0] for x in p.query.split('&') if x])))
            if key in seen:
                continue
            seen.add(key)
            out.append(u)
        except Exception:
            out.append(u)
    return out


def run_discovery(alive_hosts):
    logger.info(f"🕷️  ENDPOINT DISCOVERY ({len(alive_hosts)} hosts)")
    all_urls = []
    
    for i, host in enumerate(alive_hosts, 1):
        logger.info(f"   [{i:>3}/{len(alive_hosts)}] 🔍 {host}")
        
        # Try katana
        all_urls.extend(run_katana(host))
        try:
            dashboard.advance_recon(f"katana:{host}")
        except Exception:
            pass
        
        # Try gau
        domain = urlparse(host).netloc
        all_urls.extend(run_gau(domain))
        try:
            dashboard.advance_recon(f"gau:{domain}")
        except Exception:
            pass
        
        # Fallback to gospider if others found nothing
        if len(all_urls) < 5:
            all_urls.extend(run_gospider(host))
            try:
                dashboard.advance_recon(f"gospider:{host}")
            except Exception:
                pass

    filtered = filter_urls(all_urls)
    logger.info(f"📊 CRAWLING SUMMARY:")
    logger.info(f"   ├─ Total raw: {len(all_urls)}")
    logger.info(f"   └─ After filtering: {len(filtered)}")
    
    if not filtered:
        logger.warning("⚠️  No endpoints discovered - this may indicate all tools are unavailable")
    
    return filtered
