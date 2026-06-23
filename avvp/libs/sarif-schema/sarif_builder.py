"""
avvp/libs/sarif-schema/sarif_builder.py

Full SARIF 2.1.0 builder and structural validator.
This is the canonical implementation loaded via avvp/libs/sarif_schema/__init__.py.

Uses the same VALIDATOR_REGISTRY as core/sarif_reporter.py for consistent
CWE/OWASP mapping across both the standalone builder and the reporter.
"""

from __future__ import annotations
from typing import Any, Dict, List


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_VALID_LEVELS = {"error", "warning", "note", "none"}

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

# ── Validator-to-CWE registry (mirrors core.sarif_reporter) ──────────────────
VALIDATOR_REGISTRY: Dict[str, Dict[str, str]] = {
    "sql-injection":              {"ruleId": "CWE-89",  "name": "SQL_INJECTION",            "cwe": "CWE-89",  "owasp": "A03"},
    "reflected-xss":              {"ruleId": "CWE-79",  "name": "REFLECTED_XSS",            "cwe": "CWE-79",  "owasp": "A03"},
    "open-redirect":              {"ruleId": "CWE-601", "name": "OPEN_REDIRECT",            "cwe": "CWE-601", "owasp": "A01"},
    "sensitive-file-exposure":    {"ruleId": "CWE-538", "name": "SENSITIVE_FILE_EXPOSURE",   "cwe": "CWE-538", "owasp": "A05"},
    "csrf-missing-protections":   {"ruleId": "CWE-352", "name": "CSRF",                     "cwe": "CWE-352", "owasp": "A01"},
    "server-version-disclosure":  {"ruleId": "CWE-200", "name": "SERVER_VERSION_DISCLOSURE", "cwe": "CWE-200", "owasp": "A05"},
    "xss":                        {"ruleId": "CWE-79",  "name": "XSS",                      "cwe": "CWE-79",  "owasp": "A03"},
    "sqli":                       {"ruleId": "CWE-89",  "name": "SQL_INJECTION",            "cwe": "CWE-89",  "owasp": "A03"},
    "ssrf":                       {"ruleId": "CWE-918", "name": "SSRF",                     "cwe": "CWE-918", "owasp": "A10"},
    "ssti":                       {"ruleId": "CWE-1336","name": "SSTI",                     "cwe": "CWE-1336","owasp": "A03"},
    "lfi":                        {"ruleId": "CWE-98",  "name": "LOCAL_FILE_INCLUSION",     "cwe": "CWE-98",  "owasp": "A03"},
    "rfi":                        {"ruleId": "CWE-98",  "name": "REMOTE_FILE_INCLUSION",    "cwe": "CWE-98",  "owasp": "A03"},
    "path-traversal":             {"ruleId": "CWE-22",  "name": "PATH_TRAVERSAL",           "cwe": "CWE-22",  "owasp": "A01"},
    "cmdi":                       {"ruleId": "CWE-78",  "name": "OS_COMMAND_INJECTION",     "cwe": "CWE-78",  "owasp": "A03"},
    "idor":                       {"ruleId": "CWE-639", "name": "IDOR",                     "cwe": "CWE-639", "owasp": "A01"},
    "csrf":                       {"ruleId": "CWE-352", "name": "CSRF",                     "cwe": "CWE-352", "owasp": "A01"},
    "xxe":                        {"ruleId": "CWE-611", "name": "XXE",                      "cwe": "CWE-611", "owasp": "A05"},
    "cors":                       {"ruleId": "CWE-942", "name": "CORS_MISCONFIGURATION",    "cwe": "CWE-942", "owasp": "A05"},
    "crlf":                       {"ruleId": "CWE-93",  "name": "CRLF_INJECTION",           "cwe": "CWE-93",  "owasp": "A03"},
    "misconfiguration":           {"ruleId": "CWE-16",  "name": "MISCONFIGURATION",         "cwe": "CWE-16",  "owasp": "A05"},
    "sensitive-data-exposure":    {"ruleId": "CWE-200", "name": "SENSITIVE_DATA_EXPOSURE",   "cwe": "CWE-200", "owasp": "A02"},
    "jwt":                        {"ruleId": "CWE-287", "name": "JWT_WEAKNESS",             "cwe": "CWE-287", "owasp": "A07"},
    "graphql":                    {"ruleId": "CWE-200", "name": "GRAPHQL_INTROSPECTION",    "cwe": "CWE-200", "owasp": "A01"},
    "deserialization":            {"ruleId": "CWE-502", "name": "INSECURE_DESERIALIZATION",  "cwe": "CWE-502", "owasp": "A08"},
    "default-credentials":        {"ruleId": "CWE-798", "name": "DEFAULT_CREDENTIALS",        "cwe": "CWE-798", "owasp": "A07"},
    "no-brute-force-protection":  {"ruleId": "CWE-307", "name": "NO_BRUTE_FORCE_PROTECTION",  "cwe": "CWE-307", "owasp": "A07"},
    "insecure-session-cookie":    {"ruleId": "CWE-614", "name": "INSECURE_SESSION_COOKIE",    "cwe": "CWE-614", "owasp": "A07"},
    "idor-account-enumeration":   {"ruleId": "CWE-639", "name": "IDOR_ACCOUNT_ENUMERATION",   "cwe": "CWE-639", "owasp": "A01"},
    "cross-account-idor":         {"ruleId": "CWE-639", "name": "CROSS_ACCOUNT_IDOR",         "cwe": "CWE-639", "owasp": "A01"},
    "idor-cross-account":         {"ruleId": "CWE-639", "name": "IDOR_CROSS_ACCOUNT",         "cwe": "CWE-639", "owasp": "A01"},
    "stored-xss":                 {"ruleId": "CWE-79",  "name": "STORED_XSS",                 "cwe": "CWE-79",  "owasp": "A03"},
}


def _resolve_registry(vuln_slug: str) -> Dict[str, str]:
    """
    Look up VALIDATOR_REGISTRY for a vulnerability slug.

    Tries exact, lowercase, and substring matches.  Falls back to a
    synthetic entry so ruleId is never "unknown".
    """
    if not vuln_slug:
        return {"ruleId": "UNKNOWN", "name": "UNKNOWN", "cwe": "", "owasp": ""}

    slug = vuln_slug.strip()
    if slug in VALIDATOR_REGISTRY:
        return VALIDATOR_REGISTRY[slug]

    lower = slug.lower()
    for key, val in VALIDATOR_REGISTRY.items():
        if key.lower() == lower:
            return val

    for key, val in VALIDATOR_REGISTRY.items():
        if key in lower or lower in key:
            return val

    safe_id = slug.upper().replace("-", "_").replace(" ", "_")
    return {"ruleId": safe_id, "name": safe_id, "cwe": "", "owasp": ""}


def build_sarif_report(
    findings: List[Dict[str, Any]],
    tool_name: str = "zentry-trail",
    tool_version: str = "1.0.0",
    attack_chains: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    Build a SARIF 2.1.0 document from a list of finding dicts.

    Each finding dict should have:
      - vuln_class / vulnerability : str   rule / vulnerability class
      - severity    : str   "critical"|"high"|"medium"|"low"|"info"
      - uri / url / target_url : str   affected URL
      - summary     : str   human-readable description
      - payload     : str   confirmed payload (optional)
      - cvss        : float CVSS score (optional)
      - region      : dict  optional {startLine: int, startColumn: int}
    """
    rules   = _deduplicate_rules(findings)
    results = [_finding_to_result(f) for f in findings]

    notifications = []
    for chain in (attack_chains or []):
        notifications.append({
            "id": chain["chain_id"],
            "message": {
                "text": f"Attack Chain {chain['name']} confirmed: {chain['description']}"
            },
            "level": "error",
            "properties": {
                "severity": chain.get("severity"),
                "cvss": chain.get("cvss"),
                "owasp": chain.get("owasp"),
                "component_findings": [f.get("vulnerability") or f.get("title") for f in chain.get("component_findings", [])]
            }
        })

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
                        "notifications": notifications,
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

def _get_vuln_slug(finding: Dict[str, Any]) -> str:
    """Extract vulnerability type slug from a finding dict."""
    return str(
        finding.get("vuln_class")
        or finding.get("vulnerability")
        or finding.get("type")
        or ""
    )


def _finding_to_result(finding: Dict[str, Any]) -> Dict[str, Any]:
    vuln_slug = _get_vuln_slug(finding)
    reg       = _resolve_registry(vuln_slug)
    rule_id   = reg["ruleId"]
    severity  = str(finding.get("severity") or "info").lower()

    uri = str(
        finding.get("uri")
        or finding.get("url")
        or finding.get("target_url")
        or ""
    )

    # Human-readable message
    vuln_name = reg["name"].replace("_", " ").title()
    summary   = str(finding.get("summary") or "")
    message   = summary if summary else (f"{vuln_name} detected at {uri}" if uri else f"{vuln_name} detected")

    region = finding.get("region") or {}
    payload = str(finding.get("payload") or finding.get("confirmed_payload") or "")
    cvss    = float(finding.get("cvss") or finding.get("score") or _SEV_TO_CVSS.get(severity, 0.0))

    physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if region:
        r: Dict[str, Any] = {}
        if "startLine" in region:
            r["startLine"] = int(region["startLine"])
        if "startColumn" in region:
            r["startColumn"] = int(region["startColumn"])
        if r:
            physical["region"] = r

    level = _SEV_TO_LEVEL.get(severity, "warning")

    # Evidence bundle path from EvidenceCollector (Part E)
    bundle_path = str(
        finding.get("evidence_req_path")
        or finding.get("evidence_bundle_path")
        or ""
    )

    return {
        "ruleId":  rule_id,
        "level":   level,
        "message": {"text": message},
        "locations": [{"physicalLocation": physical}],
        "properties": {
            "severity":             severity,
            "cvss_score":           cvss,
            "confirmed_payload":    payload,
            "owasp":                reg["owasp"],
            "evidence_bundle_path": bundle_path,
        },
    }


def _deduplicate_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen  : set  = set()
    rules : list = []
    for f in findings:
        vuln_slug = _get_vuln_slug(f)
        reg       = _resolve_registry(vuln_slug)
        rule_id   = reg["ruleId"]
        if rule_id in seen:
            continue
        seen.add(rule_id)

        sev  = str(f.get("severity") or "info").lower()
        cvss = float(f.get("cvss") or f.get("score") or _SEV_TO_CVSS.get(sev, 0.0))
        cwe  = reg["cwe"]

        rule: Dict[str, Any] = {
            "id":   rule_id,
            "name": reg["name"],
            "shortDescription": {
                "text": f"{reg['name'].replace('_', ' ')} detected by zentry-trail"
            },
            "defaultConfiguration": {"level": _SEV_TO_LEVEL.get(sev, "warning")},
            "properties": {
                "cvss_score": cvss,
                "cwe":        cwe,
                "owasp":      reg["owasp"],
            },
        }

        if cwe:
            rule["relationships"] = [
                {
                    "target": {
                        "id":       cwe,
                        "guid":     "",
                        "toolComponent": {"name": "CWE"},
                    },
                    "kinds": ["superset"],
                }
            ]

        rules.append(rule)
    return rules


def _validate_run(run: Dict[str, Any], index: int) -> None:
    prefix = f"runs[{index}]"

    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise ValueError(f"{prefix}.tool must be a dict")
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        raise ValueError(f"{prefix}.tool.driver must be a dict")
    if "name" not in driver:
        raise ValueError(f"{prefix}.tool.driver must have 'name'")

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
