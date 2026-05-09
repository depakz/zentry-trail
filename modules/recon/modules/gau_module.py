"""
GAU Module - Fetch historical URLs from various sources
"""
import subprocess
import logging
import shutil
from typing import List, Set
from urllib.parse import urldefrag

logger = logging.getLogger(__name__)


def _normalize_url(url: str) -> str:
    """Strip fragments and whitespace."""
    url = url.strip()
    if not url:
        return ""
    url, _ = urldefrag(url)
    return url


def _run_gau(domains: List[str], timeout: int = 300) -> Set[str]:
    """Run gau subprocess and return URL set."""
    if not shutil.which("gau"):
        logger.error("[GAU] gau binary not found in PATH")
        return set()

    urls: Set[str] = set()
    input_data = "\n".join(domains)

    cmd = [
        "gau",
        "--threads", "10",
        "--timeout", "30",
        "--retries", "2",
        "--subs",
    ]

    try:
        logger.info(f"[GAU] Running gau on {len(domains)} domains...")
        proc = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            logger.warning(f"[GAU] non-zero exit: {proc.returncode}: {proc.stderr[:200]}")

        for line in proc.stdout.splitlines():
            norm = _normalize_url(line)
            if norm:
                urls.add(norm)

    except subprocess.TimeoutExpired:
        logger.warning(f"[GAU] Timed out after {timeout}s")
    except Exception as e:
        logger.error(f"[GAU] Error: {e}")

    return urls


def run_gau(domains: List[str], timeout: int = 300, retries: int = 2) -> List[str]:
    """
    Run gau on domain list, return deduplicated URL list.
    """
    if not domains:
        logger.warning("[GAU] No domains provided")
        return []

    domains = [d.strip() for d in domains if d.strip()]
    all_urls: Set[str] = set()

    attempt = 0
    while attempt <= retries:
        attempt += 1
        logger.info(f"[GAU] Attempt {attempt}/{retries + 1}")
        urls = _run_gau(domains, timeout=timeout)
        all_urls.update(urls)
        if all_urls:
            break
        logger.warning("[GAU] Empty output, retrying...")

    result = sorted(all_urls)
    logger.info(f"[GAU] Total unique URLs collected: {len(result)}")
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(run_gau(["example.com"]))
