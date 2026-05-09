"""
pipeline.py — Master Bug Bounty Pipeline
Hack With Yuva v3.0

Execution order (STRICT):
  Recon → Probe → Prioritize → Crawl → Deep Extraction → Filter → Scan → Validate

All stages return safe defaults on failure — no crashes on empty data.
"""

import logging
import json
import os
import sys
import time
import subprocess
import shutil
from typing import List, Dict, Optional
from datetime import datetime
from urllib.parse import urlparse

# ── Module imports ─────────────────────────────
from modules.recon.modules.gau_module       import fetch_urls        as gau_fetch
from modules.recon.modules.js_extractor     import extract_from_page, extract_from_js_urls
from modules.recon.modules.api_discovery    import discover_apis
from modules.recon.modules.param_extractor  import extract_all_params
from modules.recon.modules.post_tester      import test_post_endpoints
from modules.recon.modules.nuclei_runner    import run_smart_nuclei

# ── Optional deps ──────────────────────────────
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────

def _setup_logging(log_file: Optional[str] = None, level: int = logging.INFO):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )

logger = logging.getLogger("HWY.pipeline")


# ──────────────────────────────────────────────
# Stage helpers
# ──────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_subprocess(cmd: List[str], timeout: int = 60) -> List[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def _get_base_urls(targets: List[str]) -> List[str]:
    bases: List[str] = []
    seen: set = set()
    for t in targets:
        if not t.startswith("http"):
            t = "https://" + t
        parsed = urlparse(t)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            bases.append(base)
    return bases


# ──────────────────────────────────────────────
# STAGE 1 — Recon  (subdomain + DNS)
# ──────────────────────────────────────────────

def stage_recon(domains: List[str]) -> List[str]:
    logger.info("═══ STAGE 1: RECON ═══")
    subdomains: set = set(domains)

    tools = {
        "subfinder": lambda d: _run_subprocess(["subfinder", "-d", d, "-silent"], timeout=120),
        "assetfinder": lambda d: _run_subprocess(["assetfinder", "--subs-only", d], timeout=60),
        "amass": lambda d: _run_subprocess(
            ["amass", "enum", "-passive", "-d", d, "-timeout", "2"],
            timeout=180,
        ),
    }

    for domain in domains:
        domain = domain.strip().lstrip("http://").lstrip("https://").split("/")[0]
        for tool_name, fn in tools.items():
            if _tool_available(tool_name):
                logger.info("[RECON] Running %s on %s", tool_name, domain)
                subs = fn(domain)
                subdomains.update(subs)
                logger.info("[RECON] %s found %d subdomains", tool_name, len(subs))

    result = sorted(subdomains)
    logger.info("[RECON] Total subdomains: %d", len(result))
    return result


# ──────────────────────────────────────────────
# STAGE 2 — Probe  (alive host check)
# ──────────────────────────────────────────────

def stage_probe(subdomains: List[str]) -> List[str]:
    logger.info("═══ STAGE 2: PROBE ═══")

    if not subdomains:
        logger.warning("[PROBE] No subdomains to probe.")
        return []

    if not _tool_available("httpx"):
        logger.warning("[PROBE] httpx not found — returning all subdomains as-is.")
        return [f"https://{s}" if not s.startswith("http") else s for s in subdomains]

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(subdomains))
        inp = tf.name

    cmd = [
        "httpx", "-l", inp, "-silent", "-status-code",
        "-no-color", "-threads", "50", "-timeout", "10",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        lines = [l.strip().split()[0] for l in r.stdout.splitlines() if l.strip()]
        live = [l for l in lines if l.startswith("http")]
    except subprocess.TimeoutExpired:
        logger.warning("[PROBE] httpx timed out — falling back.")
        live = [f"https://{s}" if not s.startswith("http") else s for s in subdomains]
    finally:
        try:
            os.unlink(inp)
        except Exception:
            pass

    logger.info("[PROBE] Live hosts: %d / %d", len(live), len(subdomains))
    return live


# ──────────────────────────────────────────────
# STAGE 3 — Prioritize (scope / interesting hosts)
# ──────────────────────────────────────────────

PRIORITY_KEYWORDS = [
    "api", "admin", "auth", "login", "dev", "beta", "staging", "test",
    "app", "portal", "dashboard", "v1", "v2", "internal", "service",
    "account", "pay", "payment", "checkout", "shop", "store",
]


def stage_prioritize(live_hosts: List[str]) -> List[str]:
    logger.info("═══ STAGE 3: PRIORITIZE ═══")
    if not live_hosts:
        return []

    priority: List[str] = []
    normal:   List[str] = []

    for host in live_hosts:
        host_lower = host.lower()
        if any(kw in host_lower for kw in PRIORITY_KEYWORDS):
            priority.append(host)
        else:
            normal.append(host)

    ordered = priority + normal
    logger.info(
        "[PRIORITIZE] Priority: %d | Normal: %d | Total: %d",
        len(priority), len(normal), len(ordered),
    )
    return ordered


# ──────────────────────────────────────────────
# STAGE 4 — Crawl  (GAU + Waybackurls + Katana)
# ──────────────────────────────────────────────

def stage_crawl(live_hosts: List[str]) -> List[str]:
    logger.info("═══ STAGE 4: CRAWL ═══")

    if not live_hosts:
        logger.warning("[CRAWL] No live hosts — returning empty.")
        return []

    # Extract bare domains for GAU
    domains = []
    seen_d: set = set()
    for h in live_hosts:
        p = urlparse(h)
        d = p.netloc or h
        if d and d not in seen_d:
            seen_d.add(d)
            domains.append(d)

    # GAU / waybackurls / gauplus
    gau_result = gau_fetch(domains, timeout=90)
    urls: set = set(gau_result["urls"])
    logger.info(
        "[CRAWL] GAU status=%s, URLs=%d", gau_result["status"], len(urls)
    )

    # Katana crawler
    if _tool_available("katana"):
        logger.info("[CRAWL] Running katana on %d hosts", len(live_hosts[:20]))
        for host in live_hosts[:20]:
            katana_urls = _run_subprocess(
                ["katana", "-u", host, "-silent", "-jc", "-d", "3", "-c", "10"],
                timeout=120,
            )
            urls.update(katana_urls)
            logger.info("[CRAWL] katana → %s: %d URLs", host, len(katana_urls))
    else:
        logger.warning("[CRAWL] katana not found — skipping active crawl.")

    result = sorted(urls)
    logger.info("[CRAWL] Total URLs collected: %d", len(result))
    return result


# ──────────────────────────────────────────────
# STAGE 5 — Deep Extraction (JS + API)
# ──────────────────────────────────────────────

def stage_deep_extraction(
    live_hosts: List[str],
    crawled_urls: List[str],
) -> Dict:
    logger.info("═══ STAGE 5: DEEP EXTRACTION ═══")

    # JS extraction from live hosts
    js_data: Dict = {
        "endpoints": [], "api_routes": [], "params_urls": [],
        "param_keys": [], "websockets": [], "graphql_detected": False,
        "files_processed": 0,
    }

    for host in live_hosts[:30]:   # cap to avoid blowing runtime
        logger.info("[EXTRACT] JS analysis on: %s", host)
        result = extract_from_page(host)
        js_data["endpoints"]       += result.get("endpoints", [])
        js_data["api_routes"]      += result.get("api_routes", [])
        js_data["params_urls"]     += result.get("params_urls", [])
        js_data["param_keys"]      += result.get("param_keys", [])
        js_data["websockets"]      += result.get("websockets", [])
        js_data["files_processed"] += result.get("files_processed", 0)
        if result.get("graphql_detected"):
            js_data["graphql_detected"] = True

    # Deduplicate JS data
    for key in ["endpoints", "api_routes", "params_urls", "param_keys", "websockets"]:
        js_data[key] = sorted(set(js_data[key]))

    logger.info(
        "[EXTRACT] JS done — %d endpoints, %d API routes, %d param URLs",
        len(js_data["endpoints"]),
        len(js_data["api_routes"]),
        len(js_data["params_urls"]),
    )

    # API discovery
    all_urls_for_api = list(set(crawled_urls + js_data["endpoints"]))
    base_urls = _get_base_urls(live_hosts)

    api_endpoints = discover_apis(
        all_urls_for_api,
        base_urls=base_urls,
        active_probe=True,
    )

    return {
        "js_data":      js_data,
        "api_endpoints": api_endpoints,
        "all_urls":     list(set(crawled_urls + js_data["endpoints"])),
    }


# ──────────────────────────────────────────────
# STAGE 6 — Filter (deduplicate + normalise)
# ──────────────────────────────────────────────

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip",
}


def stage_filter(urls: List[str]) -> List[str]:
    logger.info("═══ STAGE 6: FILTER ═══")

    if not urls:
        logger.warning("[FILTER] No URLs to filter — returning empty list.")
        return []

    seen: set = set()
    filtered: List[str] = []

    for url in urls:
        url = url.strip()
        if not url.startswith("http"):
            continue
        parsed = urlparse(url)
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext in IGNORED_EXTENSIONS:
            continue
        norm = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            norm += f"?{parsed.query}"
        if norm in seen:
            continue
        seen.add(norm)
        filtered.append(url)

    logger.info("[FILTER] Filtered: %d → %d URLs", len(urls), len(filtered))
    return filtered


# ──────────────────────────────────────────────
# STAGE 7 — Scan (Nuclei + POST tester)
# ──────────────────────────────────────────────

def stage_scan(
    filtered: List[str],
    api_endpoints: List[Dict],
    parameterized_urls: Dict[str, List[str]],
    output_dir: str = ".",
) -> Dict:
    logger.info("═══ STAGE 7: SCAN ═══")

    if not filtered:
        logger.warning("[SCAN] filtered is empty — running with empty list.")

    # ── Nuclei ────────────────────────────────
    nuclei_output = os.path.join(output_dir, "nuclei_findings.json")
    nuclei_result = run_smart_nuclei(
        all_urls=filtered or [],
        api_endpoints=api_endpoints,
        parameterized_urls=parameterized_urls,
        output_file=nuclei_output,
    )
    logger.info(
        "[SCAN] Nuclei — targets=%d, findings=%d, status=%s",
        nuclei_result["targets_tested"],
        len(nuclei_result["findings"]),
        nuclei_result["status"],
    )

    # ── POST tester ───────────────────────────
    post_findings = test_post_endpoints(
        api_endpoints=api_endpoints,
        parameterized_urls=parameterized_urls,
    )
    logger.info("[SCAN] POST tester findings: %d", len(post_findings))

    return {
        "nuclei": nuclei_result,
        "post_findings": post_findings,
    }


# ──────────────────────────────────────────────
# STAGE 8 — Validate (de-dup, confidence filter)
# ──────────────────────────────────────────────

def stage_validate(scan_results: Dict) -> Dict:
    logger.info("═══ STAGE 8: VALIDATE ═══")

    nuclei_findings = scan_results.get("nuclei", {}).get("findings", [])
    post_findings   = scan_results.get("post_findings", [])

    # Filter low-confidence nuclei findings
    high_value_nuclei = [
        f for f in nuclei_findings
        if f.get("info", {}).get("severity", "").lower()
        in ("medium", "high", "critical")
    ]

    high_value_post = [
        f for f in post_findings
        if f.get("confidence", "low") in ("medium", "high")
    ]

    all_findings = high_value_nuclei + high_value_post
    logger.info(
        "[VALIDATE] Validated: nuclei=%d, post=%d, total=%d",
        len(high_value_nuclei), len(high_value_post), len(all_findings),
    )
    return {
        "nuclei_findings":   high_value_nuclei,
        "post_findings":     high_value_post,
        "total_findings":    len(all_findings),
        "all_findings":      all_findings,
    }


# ──────────────────────────────────────────────
# Master pipeline
# ──────────────────────────────────────────────

def run_pipeline(
    targets: List[str],
    output_dir: str = "output",
    run_arjun: bool = False,
    log_level: int = logging.INFO,
) -> Dict:
    """
    Full bug bounty pipeline.

    Args:
        targets:    List of domains or URLs to scan.
        output_dir: Directory to save results.
        run_arjun:  Whether to run arjun parameter discovery.
        log_level:  Python logging level.

    Returns:
        Full pipeline result dict.
    """
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "pipeline.log")
    _setup_logging(log_file=log_file, level=log_level)

    start_ts = time.time()
    logger.info("╔══════════════════════════════════════╗")
    logger.info("║  HACK WITH YUVA v3.0 — PIPELINE START ║")
    logger.info("╚══════════════════════════════════════╝")
    logger.info("Targets: %s", targets)

    # ── Default safe values (guarantee 'filtered' is always defined) ──
    subdomains:        List[str]       = []
    live_hosts:        List[str]       = []
    prioritized:       List[str]       = []
    crawled_urls:      List[str]       = []
    js_data:           Dict            = {}
    api_endpoints:     List[Dict]      = []
    all_urls:          List[str]       = []
    filtered:          List[str]       = []   # ← ALWAYS defined here
    param_data:        Dict            = {"parameterized_urls": {}, "all_param_keys": [], "arjun_results": {}}
    scan_results:      Dict            = {"nuclei": {"findings": [], "targets_tested": 0, "status": "skipped"}, "post_findings": []}
    validated:         Dict            = {"nuclei_findings": [], "post_findings": [], "total_findings": 0, "all_findings": []}

    try:
        # ── Stage 1 — Recon ────────────────────────
        subdomains = stage_recon(targets)

        # ── Stage 2 — Probe ────────────────────────
        live_hosts = stage_probe(subdomains)
        if not live_hosts:
            logger.warning("[PIPELINE] No live hosts found. Falling back to targets as hosts.")
            live_hosts = [f"https://{t}" if not t.startswith("http") else t for t in targets]

        # ── Stage 3 — Prioritize ───────────────────
        prioritized = stage_prioritize(live_hosts)

        # ── Stage 4 — Crawl ────────────────────────
        crawled_urls = stage_crawl(prioritized)

        # ── Stage 5 — Deep Extraction ──────────────
        extraction = stage_deep_extraction(prioritized, crawled_urls)
        js_data       = extraction["js_data"]
        api_endpoints = extraction["api_endpoints"]
        all_urls      = extraction["all_urls"]

        # ── Stage 6 — Filter ───────────────────────
        # 'filtered' GUARANTEED to be assigned here
        filtered = stage_filter(all_urls)

        # ── Parameter extraction (after filter) ────
        param_data = extract_all_params(
            filtered,
            js_param_keys=js_data.get("param_keys", []),
            run_arjun_flag=run_arjun,
        )
        logger.info(
            "[PIPELINE] Parameterized URLs: %d | Param keys: %d",
            len(param_data["parameterized_urls"]),
            len(param_data["all_param_keys"]),
        )

        # ── Stage 7 — Scan ─────────────────────────
        scan_results = stage_scan(
            filtered=filtered,
            api_endpoints=api_endpoints,
            parameterized_urls=param_data["parameterized_urls"],
            output_dir=output_dir,
        )

        # ── Stage 8 — Validate ─────────────────────
        validated = stage_validate(scan_results)

    except Exception as exc:
        logger.exception("[PIPELINE] Unhandled exception: %s", exc)

    # ── Summary ─────────────────────────────────
    elapsed = time.time() - start_ts
    logger.info("══════════════════════════════════════")
    logger.info("[PIPELINE] COMPLETE in %.1fs", elapsed)
    logger.info("[PIPELINE] Subdomains:        %d", len(subdomains))
    logger.info("[PIPELINE] Live hosts:        %d", len(live_hosts))
    logger.info("[PIPELINE] Crawled URLs:      %d", len(crawled_urls))
    logger.info("[PIPELINE] Filtered URLs:     %d", len(filtered))
    logger.info("[PIPELINE] API endpoints:     %d", len(api_endpoints))
    logger.info("[PIPELINE] Param URLs:        %d", len(param_data["parameterized_urls"]))
    logger.info("[PIPELINE] Total findings:    %d", validated["total_findings"])
    logger.info("══════════════════════════════════════")

    # ── Save full results ───────────────────────
    result = {
        "meta": {
            "targets":    targets,
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "elapsed_s":  round(elapsed, 2),
        },
        "subdomains":          subdomains,
        "live_hosts":          live_hosts,
        "crawled_urls":        crawled_urls,
        "filtered_urls":       filtered,
        "js_data":             js_data,
        "api_endpoints":       api_endpoints,
        "param_data":          param_data,
        "scan_results":        scan_results,
        "validated_findings":  validated,
    }

    results_file = os.path.join(output_dir, "results.json")
    try:
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info("[PIPELINE] Results saved: %s", results_file)
    except Exception as exc:
        logger.warning("[PIPELINE] Could not save results: %s", exc)

    return result
