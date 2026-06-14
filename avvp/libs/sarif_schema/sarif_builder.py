"""
avvp/libs/sarif_schema/sarif_builder.py

Lightweight SARIF 2.1.0 builder and validator.
Used by tests/test_sarif.py and core/sarif_reporter.py.
"""

from __future__ import annotations
from typing import Any, Dict, List


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_VALID_LEVELS = {"error", "warning", "note", "none"}


def build_sarif_report(
    findings: List[Dict[str, Any]],
    tool_name: str = "zentry-trail",
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """
    Build a minimal SARIF 2.1.0 document from a list of finding dicts.

    Each finding dict should have:
      - vuln_class  : str   rule / vulnerability class
      - severity    : str   "critical"|"high"|"medium"|"low"|"info"
      - uri         : str   affected URL
      - summary     : str   human-readable description
      - region      : dict  optional {startLine: int, startColumn: int}
    """
    rules   = _deduplicate_rules(findings)
    results = [_finding_to_result(f) for f in findings]

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":    tool_name,
                        "version": tool_version,
                        "rules":   rules,
                    }
                },
                "results": results,
            }
        ],
    }


def validate_sarif(sarif: Dict[str, Any]) -> None:
    """
    Validate that a SARIF dict is structurally correct (SARIF 2.1.0).

    Raises ValueError on the first structural violation found.
    Does NOT perform full JSON-Schema validation (no external dependency).
    """
    if sarif.get("version") != SARIF_VERSION:
        raise ValueError(f"Expected version '{SARIF_VERSION}', got {sarif.get('version')!r}")

    runs = sarif.get("runs")
    if not isinstance(runs, list) or len(runs) == 0:
        raise ValueError("'runs' must be a non-empty list")

    for i, run in enumerate(runs):
        _validate_run(run, index=i)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEV_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

_SEV_TO_CVSS: Dict[str, float] = {
    "critical": 9.5,
    "high":     8.0,
    "medium":   5.5,
    "low":      3.0,
    "info":     0.0,
}


def _finding_to_result(finding: Dict[str, Any]) -> Dict[str, Any]:
    vuln_class = str(finding.get("vuln_class") or "unknown")
    severity   = str(finding.get("severity") or "info").lower()
    uri        = str(finding.get("uri") or "")
    summary    = str(finding.get("summary") or vuln_class)
    region     = finding.get("region") or {}

    physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if region:
        r: Dict[str, Any] = {}
        if "startLine" in region:
            r["startLine"] = int(region["startLine"])
        if "startColumn" in region:
            r["startColumn"] = int(region["startColumn"])
        if r:
            physical["region"] = r

    return {
        "ruleId":  vuln_class,
        "level":   _SEV_TO_LEVEL.get(severity, "warning"),
        "message": {"text": summary},
        "locations": [{"physicalLocation": physical}],
        "properties": {
            "severity":   severity,
            "cvss_score": _SEV_TO_CVSS.get(severity, 0.0),
        },
    }


def _deduplicate_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen  : set    = set()
    rules : list   = []
    for f in findings:
        vc = str(f.get("vuln_class") or "unknown")
        if vc in seen:
            continue
        seen.add(vc)
        sev  = str(f.get("severity") or "info").lower()
        rules.append({
            "id":   vc,
            "name": vc.upper().replace("_", " "),
            "shortDescription": {"text": f"{vc.upper()} detected"},
            "defaultConfiguration": {"level": _SEV_TO_LEVEL.get(sev, "warning")},
            "properties": {"cvss_score": _SEV_TO_CVSS.get(sev, 0.0)},
        })
    return rules


def _validate_run(run: Dict[str, Any], index: int) -> None:
    prefix = f"runs[{index}]"

    # tool
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise ValueError(f"{prefix}.tool must be a dict")
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        raise ValueError(f"{prefix}.tool.driver must be a dict")
    if "name" not in driver:
        raise ValueError(f"{prefix}.tool.driver must have 'name'")

    # results
    results = run.get("results")
    if not isinstance(results, list):
        raise ValueError(f"{prefix}.results must be a list")

    for j, result in enumerate(results):
        rprefix = f"{prefix}.results[{j}]"
        if "ruleId" not in result:
            raise ValueError(f"{rprefix} missing 'ruleId'")
        level = result.get("level", "warning")
        if level not in _VALID_LEVELS:
            raise ValueError(f"{rprefix}.level must be one of {_VALID_LEVELS}, got {level!r}")
        if "message" not in result:
            raise ValueError(f"{rprefix} missing 'message'")
        locs = result.get("locations", [])
        if not isinstance(locs, list):
            raise ValueError(f"{rprefix}.locations must be a list")
