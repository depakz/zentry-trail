"""
SARIF 2.1.0 reporter for zentry-trail scan findings.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


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

SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

TOOL_NAME    = "zentry-trail"
TOOL_VERSION = "1.0.0"
TOOL_URI     = "https://github.com/zentry-trail/zentry-trail"

CWE_TAXONOMY_URI = "https://cwe.mitre.org/data/definitions/"


def _resolve_registry(vuln_slug: str) -> Dict[str, str]:
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


class SARIFReporter:
    """
    Generates SARIF 2.1.0 compliant output from scan findings.
    """

    def generate(
        self,
        findings: list | None = None,
        target: str = "",
        evidence_store=None,
        scan_id: Optional[str] = None,
        attack_chains: list | None = None,
        *,
        session=None,
    ) -> Dict[str, Any]:
        if findings is None and session is not None:
            raw = getattr(session, "findings", []) or []
            findings = []
            for f in raw:
                if isinstance(f, dict):
                    findings.append(f)
                else:
                    findings.append({
                        "vulnerability": getattr(f, "title", "") or "",
                        "target_url":    getattr(f, "endpoint", "") or "",
                        "severity":      getattr(f, "severity", "info") or "info",
                        "payload":       getattr(f, "payload", "") or "",
                        "cvss":          getattr(f, "score", 0.0) or 0.0,
                        "score":         getattr(f, "score", 0.0) or 0.0,
                        "id":            getattr(f, "id", "") or "",
                        "evidence":      getattr(f, "evidence", "") or "",
                    })
            target = target or str(getattr(session, "target", ""))
            scan_id = scan_id or getattr(session, "scan_id", None)

        findings = findings or []
        sid = scan_id or str(int(time.time()))

        rules   = self._build_rules(findings)
        results = self._build_results(findings, evidence_store)

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

        sarif: Dict[str, Any] = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name":           TOOL_NAME,
                            "version":        TOOL_VERSION,
                            "informationUri": TOOL_URI,
                            "rules":          rules,
                            "notifications":  notifications,
                        }
                    },
                    "results":  results,
                    "taxonomies": self._build_cwe_taxonomy(findings),
                    "properties": {
                        "scan_id": sid,
                        "target":  target,
                        "generated_at": int(time.time()),
                    },
                }
            ],
        }
        return sarif

    def write(self, sarif: Dict[str, Any], output_path: str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sarif, indent=2))
        return str(path)

    def _get_vuln_slug(self, finding: dict) -> str:
        return str(
            finding.get("vulnerability")
            or finding.get("vuln_class")
            or finding.get("title")
            or finding.get("type")
            or ""
        )

    def _build_rules(self, findings: list) -> List[Dict]:
        seen:  set  = set()
        rules: list = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            vuln_slug = self._get_vuln_slug(finding)
            reg       = _resolve_registry(vuln_slug)
            rule_id   = reg["ruleId"]

            if rule_id in seen:
                continue
            seen.add(rule_id)

            severity = str(finding.get("severity") or "info").lower()
            cvss     = float(finding.get("cvss") or 0.0)
            cwe      = reg["cwe"]
            owasp    = reg["owasp"]

            rule: Dict[str, Any] = {
                "id":   rule_id,
                "name": reg["name"],
                "shortDescription": {
                    "text": f"{reg['name'].replace('_', ' ')} vulnerability detected by zentry-trail"
                },
                "helpUri": f"{CWE_TAXONOMY_URI}{cwe.replace('CWE-', '')}.html" if cwe else TOOL_URI,
                "properties": {
                    "severity":   severity,
                    "cvss_score": cvss,
                    "tags":       ["security", vuln_slug, cwe, owasp] if cwe else ["security", vuln_slug],
                },
                "defaultConfiguration": {
                    "level": SEVERITY_TO_LEVEL.get(severity, "warning")
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

    def _build_results(self, findings: list, evidence_store) -> List[Dict]:
        results = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            vuln_slug  = self._get_vuln_slug(finding)
            reg        = _resolve_registry(vuln_slug)
            rule_id    = reg["ruleId"]
            severity   = str(finding.get("severity") or "info").lower()

            uri = str(
                finding.get("target_url")
                or finding.get("url")
                or finding.get("uri")
                or finding.get("endpoint")
                or ""
            )

            vuln_name = reg["name"].replace("_", " ").title()
            message   = f"{vuln_name} detected at {uri}" if uri else f"{vuln_name} detected"

            payload = str(
                finding.get("payload")
                or finding.get("confirmed_payload")
                or ""
            )

            cvss = float(finding.get("cvss") or finding.get("score") or 0.0)

            finding_id  = str(finding.get("id") or finding.get("finding_id") or "")
            parent_id   = finding.get("parent_finding_id") or finding.get("chain_parent_id")
            owasp       = finding.get("owasp") or reg["owasp"]

            bundle_path = str(finding.get("evidence_req_path") or "")
            if not bundle_path and evidence_store and finding_id:
                try:
                    bundle_dir = Path(evidence_store.output_dir) / finding_id / "bundle.json"
                    if bundle_dir.exists():
                        bundle_path = str(bundle_dir)
                except Exception:
                    pass

            result: Dict[str, Any] = {
                "ruleId":  rule_id,
                "level":   SEVERITY_TO_LEVEL.get(severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region":           {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "cvss_score":           cvss,
                    "severity":             severity,
                    "confirmed_payload":    payload,
                    "owasp":                owasp,
                    "evidence_bundle_path": bundle_path,
                },
            }

            if parent_id:
                result["relatedLocations"] = [
                    {
                        "id":      0,
                        "message": {"text": f"Chain parent finding: {parent_id}"},
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                        },
                    }
                ]

            results.append(result)

        return results

    def _build_cwe_taxonomy(self, findings: list) -> List[Dict]:
        seen_cwes: set = set()
        taxa: list = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            vuln_slug = self._get_vuln_slug(finding)
            reg = _resolve_registry(vuln_slug)
            cwe = reg["cwe"]
            if cwe and cwe not in seen_cwes:
                seen_cwes.add(cwe)
                cwe_id = cwe.replace("CWE-", "")
                taxa.append({
                    "id":   cwe,
                    "name": reg["name"].replace("_", " "),
                    "shortDescription": {
                        "text": f"{reg['name'].replace('_', ' ')} ({cwe})"
                    },
                    "helpUri": f"{CWE_TAXONOMY_URI}{cwe_id}.html",
                })

        if not taxa:
            return []

        return [
            {
                "name":               "CWE",
                "version":            "4.14",
                "informationUri":     "https://cwe.mitre.org/",
                "organization":       "MITRE",
                "shortDescription":   {"text": "Common Weakness Enumeration"},
                "taxa":               taxa,
                "isComprehensive":    False,
            }
        ]
