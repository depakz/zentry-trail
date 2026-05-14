"""HTML/JSON reporting writer for the orchestration pipeline."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader


def _safe_target(value: str) -> str:
    target = re.sub(r"^https?://", "", str(value or "")).strip().strip("/")
    return re.sub(r"[^A-Za-z0-9._-]", "_", target) or "target"


def _severity_counts(findings: list[dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _owasp_mapping(vuln: str, validator_name: str) -> str:
    key = f"{vuln} {validator_name}".lower()
    mapping = [
        ("access-control", "A01: Broken Access Control"),
        ("crypto", "A02: Cryptographic Failures"),
        ("injection", "A03: Injection"),
        ("insecure-design", "A04: Insecure Design"),
        ("misconfiguration", "A05: Security Misconfiguration"),
        ("outdated", "A06: Vulnerable and Outdated Components"),
        ("auth", "A07: Identification and Authentication Failures"),
        ("deserialization", "A08: Software and Data Integrity Failures"),
        ("headers", "A05: Security Misconfiguration"),
        ("ssrf", "A10: Server-Side Request Forgery"),
        ("xss", "A03: Injection"),
        ("csrf", "A01: Broken Access Control"),
        ("idor", "A01: Broken Access Control"),
        ("graphql", "A01: Broken Access Control"),
        ("jwt", "A07: Identification and Authentication Failures"),
    ]
    for token, label in mapping:
        if token in key:
            return label
    return "A09: Security Logging and Monitoring Failures"


def _finding_details(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for finding in findings:
        validator_name = str(finding.get("validator_name") or finding.get("title") or "unknown_validator")
        target_url = str(finding.get("target_url") or finding.get("endpoint") or "")
        payload = str(finding.get("payload") or "")
        snippet = str(finding.get("response_snippet") or finding.get("evidence") or "")
        cvss = float(finding.get("cvss") or finding.get("score") or 0.0)
        vuln = str(finding.get("vulnerability") or finding.get("title") or "")
        output.append(
            {
                **finding,
                "validator_name": validator_name,
                "target_url": target_url,
                "payload": payload,
                "response_snippet": snippet,
                "cvss": cvss,
                "owasp": _owasp_mapping(vuln, validator_name),
            }
        )
    return output


def _load_template_env() -> Environment:
    template_dir = Path(__file__).resolve().parent / "templates"
    return Environment(loader=FileSystemLoader(str(template_dir)))


def build_report(session: Any, report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = report_payload or {}
    findings = payload.get("findings") or []
    if not findings and hasattr(session, "findings"):
        raw_findings = getattr(session, "findings") or []
        findings = [f if isinstance(f, dict) else vars(f) for f in raw_findings]

    detail_items = _finding_details(findings)
    summary = _severity_counts(detail_items)

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": getattr(session, "target", ""),
        "timestamp": str(getattr(session, "data", {}).get("created") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")),
        "executive_summary": {
            "total_findings": len(detail_items),
            "severity": summary,
        },
        "attack_chains": payload.get("attack_chains") or [],
        "findings": detail_items,
        "signal_coverage": payload.get("signal_coverage") or {},
    }
    return report


def write(session: Any, out_dir: str = "reports", report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Write both HTML and JSON reports and return their paths."""
    output_dir = Path(out_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    report = build_report(session, report_payload=report_payload)
    slug = _safe_target(report.get("target", "target"))
    stamp = str(report.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S"))
    base = f"{slug}-{stamp}-report"

    env = _load_template_env()
    tpl = env.get_template("report.html.j2")
    html = tpl.render(r=report)

    html_path = output_dir / f"{base}.html"
    json_path = output_dir / f"{base}.json"
    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    return {"html": str(html_path), "json": str(json_path)}
