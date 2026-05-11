"""
GAU Runner with retry + waybackurls fallback.
"""
import subprocess
import logging
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger("gau_runner")
from core.logger import dashboard


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(cmd: list, stdin_data: str = "", timeout: int = 60) -> str:
    try:
        p = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return p.stdout or ""
    except subprocess.TimeoutExpired:
        log.warning(f"⏱️  TIMEOUT: {' '.join(cmd)[:80]}")
        return ""
    except Exception as e:
        log.warning(f"❌ FAIL: {' '.join(cmd)[:60]} -> {e}")
        return ""


def _run_gau_single(domain: str, threads: int = 3, timeout: int = 30) -> list:
    """
    Run gau with provider fallback chain. Retry once with reduced threads.
    """
    if not _have("gau"):
        return []

    providers = "wayback,commoncrawl,otx"
    for attempt in range(2):
        t = threads if attempt == 0 else max(1, threads - 1)
        cmd = [
            "gau",
            "--providers", providers,
            "--threads", str(t),
            "--timeout", "10",
            "--subs",
            domain
        ]
        out = _run(cmd, timeout=timeout)
        if out.strip():
            urls = [u.strip() for u in out.splitlines() if u.strip().startswith("http")]
            log.info(f"   ✓ gau({domain}): {len(urls)} URLs")
            try:
                dashboard.advance_recon(f"gau:{domain}")
            except Exception:
                pass
            return urls
    return []


def _run_waybackurls(domain: str, timeout: int = 30) -> list:
    if not _have("waybackurls"):
        return []
    cmd = ["waybackurls", domain]
    out = _run(cmd, timeout=timeout)
    urls = [u.strip() for u in out.splitlines() if u.strip().startswith("http")]
    if urls:
        log.info(f"   ✓ waybackurls({domain}): {len(urls)} URLs")
        try:
            dashboard.advance_recon(f"wayback:{domain}")
        except Exception:
            pass
    return urls


def run_gau(domains: list, max_workers: int = 4, timeout: int = 30) -> list:
    """
    Public entrypoint. Returns deduped historical URL list.
    """
    if isinstance(domains, str):
        domains = [domains]

    domains = list({d.replace("https://", "").replace("http://", "").strip("/") for d in domains})
    log.info(f"📜 GAU: querying {len(domains)} domains (gau→waybackurls fallback)")

    all_urls = set()

    def _worker(domain):
        urls = _run_gau_single(domain, timeout=timeout)
        if not urls:
            urls = _run_waybackurls(domain, timeout=timeout)
        return urls

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_worker, d): d for d in domains}
        for f in as_completed(futs):
            try:
                all_urls.update(f.result())
            except Exception as e:
                log.debug(f"gau worker err: {e}")

    log.info(f"📜 GAU total: {len(all_urls)} unique historical URLs")
    return sorted(all_urls)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(len(run_gau(["example.com"])))
