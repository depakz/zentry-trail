from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit


RECON_ROOT = Path(__file__).resolve().parents[2] / "RECON-ZENTRY"


class _ReconSessionShim:
    def __init__(self, target: str):
        self.target = target
        self.values: Dict[str, Any] = {}

    def update(self, key: str, value: Any) -> Any:
        self.values[key] = value
        return value

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


def _ensure_recon_path() -> None:
    if not RECON_ROOT.exists():
        raise FileNotFoundError(f"RECON-ZENTRY root not found: {RECON_ROOT}")

    recon_root = str(RECON_ROOT)
    if recon_root not in sys.path:
        sys.path.insert(0, recon_root)


def _load_recon_modules() -> Dict[str, ModuleType]:
    _ensure_recon_path()
    return {
        "recon": importlib.import_module("modules.recon"),
        "probe": importlib.import_module("modules.probe"),
        "discovery": importlib.import_module("modules.discovery"),
        "param_miner": importlib.import_module("modules.param_miner"),
        "smart_filter": importlib.import_module("modules.smart_filter"),
        "response_analyzer": importlib.import_module("modules.response_analyzer"),
        "nuclei_scanner": importlib.import_module("modules.nuclei_scanner"),
    }


def _load_recon_main_module() -> ModuleType:
    _ensure_recon_path()
    main_path = RECON_ROOT / "main.py"
    spec = importlib.util.spec_from_file_location("recon_zentry_main", main_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load RECON-ZENTRY main.py from {main_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _as_target_domain(target: str) -> str:
    if not isinstance(target, str):
        return ""

    candidate = target.strip()
    if not candidate:
        return ""

    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or parsed.netloc or candidate).strip().lower()


def _is_http_url(value: Any) -> bool:
    return isinstance(value, str) and value.strip().startswith(("http://", "https://"))


def _normalize_http_url(value: Any) -> Optional[str]:
    if not _is_http_url(value):
        return None

    candidate = value.strip()
    parsed = urlsplit(candidate)
    if not parsed.scheme or not parsed.netloc:
        return None
    return candidate


def _dedupe_http_urls(values: Iterable[Any]) -> List[str]:
    deduped: List[str] = []
    seen = set()

    for value in values:
        normalized = _normalize_http_url(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)

    return deduped


def _extract_url(value: Any) -> Optional[str]:
    if isinstance(value, str):
        return _normalize_http_url(value)
    if isinstance(value, dict):
        return _normalize_http_url(value.get("url"))
    return None


def _urls_from_ranked_targets(ranked_targets: Iterable[Any]) -> List[str]:
    urls: List[str] = []
    for entry in ranked_targets or []:
        url = _extract_url(entry)
        if url:
            urls.append(url)
    return urls


def _params_as_list(param_map: Any) -> List[Dict[str, Any]]:
    if not isinstance(param_map, dict):
        return []

    normalized: List[Dict[str, Any]] = []
    for url, values in sorted(param_map.items(), key=lambda item: str(item[0])):
        if not isinstance(url, str):
            continue
        if isinstance(values, (list, tuple, set)):
            params = sorted({str(value) for value in values if str(value).strip()})
        elif values:
            params = [str(values)]
        else:
            params = []
        normalized.append({"url": url, "params": params})
    return normalized


def _severity_summary(findings: Iterable[Any]) -> Dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_score": 0}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or finding.get("info", {}).get("severity") or "info").strip().lower()
        if severity not in summary:
            severity = "info"
        summary[severity] += 1

    summary["risk_score"] = (
        summary["critical"] * 10
        + summary["high"] * 7
        + summary["medium"] * 4
        + summary["low"]
    )
    return summary


def _build_scan_info(target: str, subdomains: List[str], alive_hosts: List[str], endpoints: List[str], ranked_targets: List[Any], findings: List[Any]) -> Dict[str, Any]:
    return {
        "target": target,
        "source": "recon_zentry",
        "subdomains": len(subdomains),
        "alive_hosts": len(alive_hosts),
        "endpoints": len(endpoints),
        "ranked_targets": len(ranked_targets),
        "findings": len(findings),
    }


def _build_summary(findings: List[Any]) -> Dict[str, int]:
    return _severity_summary(findings)


async def run_recon_zentry(target: str) -> Dict[str, Any]:
    try:
        main_module = _load_recon_main_module()
        runner = getattr(main_module, "run_recon_pipeline", None)
        if callable(runner):
            parsed = await runner(target)
            if isinstance(parsed, dict):
                normalized = dict(parsed)
                normalized["target"] = target
                normalized["source"] = "recon_zentry"
                normalized.setdefault("scan_info", {})
                normalized.setdefault("summary", _build_summary(normalized.get("findings", [])))
                normalized["subdomains"] = [item for item in normalized.get("subdomains", []) if isinstance(item, str)]
                normalized["alive_hosts"] = _dedupe_http_urls(normalized.get("alive_hosts", []))
                normalized["endpoints"] = _dedupe_http_urls(normalized.get("endpoints", []))
                normalized["validation_targets"] = _dedupe_http_urls(normalized.get("validation_targets", []))
                normalized["ranked_targets"] = normalized.get("ranked_targets", []) if isinstance(normalized.get("ranked_targets", []), list) else []
                normalized["params"] = normalized.get("params", []) if isinstance(normalized.get("params", []), list) else []
                normalized["categories"] = normalized.get("categories", []) if isinstance(normalized.get("categories", []), list) else []
                normalized["findings"] = normalized.get("findings", []) if isinstance(normalized.get("findings", []), list) else []
                normalized["vulnerabilities"] = normalized.get("vulnerabilities", normalized["findings"])
                normalized["response_analysis"] = normalized.get("response_analysis", {}) if isinstance(normalized.get("response_analysis", {}), dict) else {}
                return normalized
    except Exception:
        pass

    modules = _load_recon_modules()
    session = _ReconSessionShim(target=target)

    target_domain = _as_target_domain(target)
    if not target_domain:
        empty_findings: List[Any] = []
        return {
            "target": target,
            "subdomains": [],
            "alive_hosts": [],
            "endpoints": [],
            "validation_targets": [],
            "ranked_targets": [],
            "params": [],
            "categories": [],
            "findings": [],
            "vulnerabilities": [],
            "response_analysis": {},
            "source": "recon_zentry",
            "scan_info": _build_scan_info(target, [], [], [], [], empty_findings),
            "summary": _build_summary(empty_findings),
        }

    recon = modules["recon"]
    probe = modules["probe"]
    discovery = modules["discovery"]
    param_miner = modules["param_miner"]
    smart_filter = modules["smart_filter"]
    response_analyzer = modules["response_analyzer"]
    nuclei_scanner = modules["nuclei_scanner"]

    subdomains = await asyncio.to_thread(recon.run_recon, target_domain)
    if not isinstance(subdomains, list):
        subdomains = []

    alive_hosts = await asyncio.to_thread(probe.run_probe, subdomains)
    if not isinstance(alive_hosts, list):
        alive_hosts = []
    alive_hosts = _dedupe_http_urls(alive_hosts)

    endpoints = await asyncio.to_thread(discovery.run_discovery, alive_hosts)
    if not isinstance(endpoints, list):
        endpoints = []
    endpoints = _dedupe_http_urls(endpoints)

    alive_hostnames = []
    for host in alive_hosts:
        parsed = urlsplit(host)
        if parsed.hostname:
            alive_hostnames.append(parsed.hostname)
        elif parsed.netloc:
            alive_hostnames.append(parsed.netloc)
    alive_hostnames = sorted({host for host in alive_hostnames if host})

    extra_urls, param_map = await param_miner.mine_parameters(alive_hostnames, endpoints, session)
    if not isinstance(extra_urls, list):
        extra_urls = []
    if not isinstance(param_map, dict):
        param_map = {}

    all_endpoints = _dedupe_http_urls([*endpoints, *extra_urls, *alive_hosts])

    ranked_targets = smart_filter.filter_and_rank(all_endpoints)
    if not isinstance(ranked_targets, list):
        ranked_targets = []

    category_map = smart_filter.summarize(ranked_targets, session)
    if not isinstance(category_map, dict):
        category_map = {}

    ranked_urls = _urls_from_ranked_targets(ranked_targets)
    validation_targets = _dedupe_http_urls([*ranked_urls, *all_endpoints, target])

    response_analysis = await response_analyzer.analyze(ranked_urls, session)
    if not isinstance(response_analysis, dict):
        response_analysis = {}

    nuclei_findings = await nuclei_scanner.scan_with_nuclei(all_endpoints, session)
    if not isinstance(nuclei_findings, list):
        nuclei_findings = []

    categories = sorted(category_map.keys())
    params = _params_as_list(param_map)
    summary = _build_summary(nuclei_findings)

    return {
        "target": target,
        "subdomains": subdomains,
        "alive_hosts": alive_hosts,
        "endpoints": all_endpoints,
        "validation_targets": validation_targets,
        "ranked_targets": ranked_targets,
        "params": params,
        "categories": categories,
        "findings": nuclei_findings,
        "vulnerabilities": list(nuclei_findings),
        "response_analysis": response_analysis,
        "source": "recon_zentry",
        "scan_info": _build_scan_info(target, subdomains, alive_hosts, all_endpoints, ranked_targets, nuclei_findings),
        "summary": summary,
        "category_map": category_map,
        "extra_urls": _dedupe_http_urls(extra_urls),
        "session_context": dict(getattr(session, "values", {})),
    }
