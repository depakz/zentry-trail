"""Endpoint discovery: katana + gau"""
import subprocess, shutil, tempfile
from pathlib import Path
from urllib.parse import urlparse
from core.logger import logger

def run_katana(url):
    if not shutil.which("katana"):
        return []
    try:
        r = subprocess.run(
            ["katana", "-u", url, "-silent", "-d", "2",
             "-jc", "-kf", "all", "-c", "10", "-timeout", "10",
             "-rl", "100"],
            capture_output=True, text=True, timeout=120
        )
        urls = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
        logger.info(f"      └─ katana: {len(urls)} URLs")
        return urls
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  katana timeout for {url}")
        return []
    except Exception as e:
        logger.error(f"katana error: {e}")
        return []

def run_gau(domain):
    if not shutil.which("gau"):
        return []
    try:
        r = subprocess.run(
            ["gau", "--threads", "3", "--timeout", "15", domain],
            capture_output=True, text=True, timeout=60
        )
        urls = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
        logger.info(f"      └─ gau: {len(urls)} URLs")
        return urls
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  gau timeout for {domain}")
        return []
    except Exception:
        return []

def filter_urls(urls):
    """Remove static junk"""
    skip_ext = (".png",".jpg",".jpeg",".gif",".svg",".ico",".css",".woff",
                ".woff2",".ttf",".eot",".mp4",".webp")
    out = []
    seen = set()
    for u in urls:
        if u.lower().endswith(skip_ext): continue
        # dedupe by path+param-keys (ignore values)
        try:
            p = urlparse(u)
            key = (p.netloc, p.path, tuple(sorted([x.split('=')[0] for x in p.query.split('&') if x])))
            if key in seen: continue
            seen.add(key)
            out.append(u)
        except: out.append(u)
    return out

def run_discovery(alive_hosts):
    logger.info(f"🕷️  ENDPOINT DISCOVERY ({len(alive_hosts)} hosts)")
    all_urls = []
    for i, host in enumerate(alive_hosts, 1):
        logger.info(f"   [{i:>3}/{len(alive_hosts)}] 🔍 {host}")
        all_urls.extend(run_katana(host))
        domain = urlparse(host).netloc
        all_urls.extend(run_gau(domain))

    filtered = filter_urls(all_urls)
    logger.info(f"📊 CRAWLING SUMMARY:")
    logger.info(f"   ├─ Total raw: {len(all_urls)}")
    logger.info(f"   └─ After filtering: {len(filtered)}")
    return filtered
