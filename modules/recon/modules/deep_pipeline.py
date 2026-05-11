"""
Deep Pipeline Orchestrator
"""
import logging
from typing import List, Dict
from urllib.parse import urlparse

from modules.recon.modules.gau_module import run_gau
from modules.recon.modules.js_extractor import extract_js_endpoints
from modules.recon.modules.api_discovery import discover_apis
from modules.recon.modules.post_tester import extract_params, run_post_tests
from core.logger import dashboard

logger = logging.getLogger(__name__)


def _hosts_to_domains(hosts: List[str]) -> List[str]:
    domains = set()
    for h in hosts:
        h = h.strip()
        if not h:
            continue
        if "://" in h:
            try:
                domains.add(urlparse(h).netloc)
            except Exception:
                pass
        else:
            domains.add(h.split("/")[0])
    return sorted(d for d in domains if d)


def run_deep_pipeline(
    katana_urls: List[str],
    tier1_hosts: List[str],
    enable_post_test: bool = True,
) -> Dict:
    """
    Run full deep recon pipeline.
    Returns: {merged_urls, apis, params, post_findings}
    """
    logger.info("=" * 60)
    logger.info("[DEEP] Starting deep pipeline")
    logger.info("=" * 60)

    katana_urls = katana_urls or []
    tier1_hosts = tier1_hosts or []

    # 1. GAU
    domains = _hosts_to_domains(tier1_hosts)
    logger.info(f"[DEEP] Running GAU on {len(domains)} domains")
    gau_urls: List[str] = []
    try:
        gau_urls = run_gau(domains) if domains else []
    except Exception as e:
        logger.error(f"[DEEP] GAU failed: {e}")
    try:
        dashboard.advance_recon(f"deep:gau:{len(gau_urls)}")
    except Exception:
        pass

    # 2. Merge
    merged = set(katana_urls) | set(gau_urls)
    merged_list = sorted(merged)
    logger.info(f"[DEEP] Merged: katana={len(katana_urls)} gau={len(gau_urls)} total={len(merged_list)}")

    # 3. JS extraction
    js_data = {"js_files": [], "endpoints": []}
    try:
        js_data = extract_js_endpoints(merged_list)
    except Exception as e:
        logger.error(f"[DEEP] JS extractor failed: {e}")
    try:
        dashboard.advance_recon(f"deep:js_extracted:{len(js_data.get('endpoints', []))}")
    except Exception:
        pass

    if js_data["endpoints"]:
        merged.update(js_data["endpoints"])
        merged_list = sorted(merged)

    # 4. API discovery
    apis: List[Dict] = []
    try:
        apis = discover_apis(merged_list)
    except Exception as e:
        logger.error(f"[DEEP] API discovery failed: {e}")
    try:
        dashboard.advance_recon(f"deep:apis:{len(apis)}")
    except Exception:
        pass

    # 5. Param extraction
    params: List[Dict] = []
    try:
        params = extract_params(merged_list)
    except Exception as e:
        logger.error(f"[DEEP] Param extraction failed: {e}")
    try:
        dashboard.advance_recon(f"deep:params:{len(params)}")
    except Exception:
        pass

    # 6. POST testing
    post_findings: List[Dict] = []
    if enable_post_test and params:
        try:
            post_findings = run_post_tests(params)
        except Exception as e:
            logger.error(f"[DEEP] POST tester failed: {e}")
        try:
            dashboard.advance_recon(f"deep:post_tests:{len(post_findings)}")
        except Exception:
            pass
    else:
        logger.info("[DEEP] POST testing skipped")

    result = {
        "merged_urls": merged_list,
        "apis": apis,
        "params": params,
        "post_findings": post_findings,
        "js_files": js_data["js_files"],
        "js_endpoints": js_data["endpoints"],
    }

    logger.info("=" * 60)
    logger.info(
        f"[DEEP] Done. urls={len(merged_list)} apis={len(apis)} "
        f"params={len(params)} post_findings={len(post_findings)}"
    )
    logger.info("=" * 60)
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    out = run_deep_pipeline([], ["example.com"], enable_post_test=False)
    print(out.keys())
