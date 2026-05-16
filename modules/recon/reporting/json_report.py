"""JSON recon report writer and FactStore bridge."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from core.signatures import check_juice_shop_error
from modules.pipeline.brain.fact_store import Fact, FactCategory, FactStore


def _safe_target(value: str) -> str:
    target = re.sub(r"^https?://", "", str(value or "")).strip().strip("/")
    return re.sub(r"[^A-Za-z0-9._-]", "_", target) or "target"


def _ensure_dicts(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def build_report(session: Any, report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = report_payload or {}
    findings = _ensure_dicts(payload.get("findings") or [])
    signal_coverage = payload.get("signal_coverage") if isinstance(payload.get("signal_coverage"), dict) else {}

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": getattr(session, "target", ""),
        "timestamp": str(getattr(session, "data", {}).get("created") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")),
        "summary": {
            "total_findings": len(findings),
            "confirmed_findings": sum(
                1
                for finding in findings
                if bool(finding.get("success")) or str((finding.get("validation") or {}).get("status") or "").lower() == "confirmed"
            ),
        },
        "findings": findings,
        "signal_coverage": signal_coverage,
        "attack_chains": payload.get("attack_chains") or [],
    }


def write(session: Any, out_dir: str = "reports", report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    output_dir = Path(out_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    report = build_report(session, report_payload=report_payload)
    slug = _safe_target(report.get("target", "target"))
    stamp = str(report.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S"))
    path = output_dir / f"{slug}-{stamp}-recon-report.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return {"json": str(path)}


def _ingest_signal_coverage(report: Dict[str, Any], fact_store: FactStore) -> int:
    count = 0
    signal_coverage = report.get("signal_coverage") if isinstance(report.get("signal_coverage"), dict) else {}
    detected = signal_coverage.get("detected_signals") if isinstance(signal_coverage.get("detected_signals"), dict) else {}
    tech = detected.get("tech") if isinstance(detected.get("tech"), list) else []

    for item in tech:
        if not isinstance(item, str) or not item.strip():
            continue
        fact_store.add_fact(
            Fact(
                category=FactCategory.SERVICE_INFO,
                key=f"tech:{item.strip().lower()}",
                value={"technology": item.strip()},
                confidence=0.9,
                metadata={"source": "recon_report"},
            )
        )
        count += 1

    return count


def _ingest_finding(fact_store: FactStore, finding: Dict[str, Any]) -> bool:
    severity = str(finding.get("severity") or (finding.get("validation") or {}).get("severity") or "info").lower()
    success = bool(finding.get("success")) or str((finding.get("validation") or {}).get("status") or "").lower() == "confirmed"
    if severity not in {"critical", "high"} and not success and not check_juice_shop_error(finding):
        return False

    validator_id = str(finding.get("validator_id") or finding.get("validator_name") or finding.get("vulnerability") or "recon_finding")
    vuln_type = str(finding.get("vulnerability") or finding.get("type") or validator_id)
    target = str(finding.get("target") or finding.get("target_url") or finding.get("matched_url") or finding.get("url") or "")
    confidence = 0.99 if severity in {"critical", "high"} or success else 0.9

    fact_store.add_confirmed_vulnerability(
        vuln_id=f"recon:{validator_id}:{vuln_type}",
        vuln_type=vuln_type,
        target=target,
        confidence=confidence,
        source_validator_id=validator_id,
        metadata={
            "severity": severity,
            "source": "recon_report",
            "finding": finding,
        },
    )
    return True


def ingest_report(report: Dict[str, Any], fact_store: FactStore) -> int:
    if not isinstance(report, dict):
        return 0

    imported = _ingest_signal_coverage(report, fact_store)

    findings = _ensure_dicts(report.get("findings") or [])
    for finding in findings:
        if _ingest_finding(fact_store, finding):
            imported += 1

    return imported


def load_into_fact_store(report_path: str, fact_store: FactStore) -> int:
    if not report_path:
        return 0

    path = Path(report_path)
    if not path.exists():
        return 0

    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0

    return ingest_report(report, fact_store)
