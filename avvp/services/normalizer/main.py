import json
from typing import Dict, Any
from avvp.libs.sarif_schema import build_sarif_report, validate_sarif
from avvp.libs.event_schemas.schemas import ReconNormalizedEvent


def normalize_finding(scan_id: str, finding: Dict[str, Any]) -> ReconNormalizedEvent:
    # Convert an internal finding dict into a SARIF-based normalized event
    sarif = build_sarif_report([finding])
    # validate sarif minimally
    validate_sarif(sarif)
    payload = {
        "finding_id": finding.get("finding_id"),
        "vuln_class": finding.get("vuln_class"),
        "severity": finding.get("severity"),
        "sarif": sarif,
    }
    return ReconNormalizedEvent(scan_id=scan_id, payload=payload)
