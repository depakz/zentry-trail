"""
SARIF 2.1.0 reporter for zentry-trail scan findings.

Produces SARIF (Static Analysis Results Interchange Format) output that
integrates with GitHub Code Scanning, VS Code, and CI/CD pipelines.

Usage:
    from core.sarif_reporter import SARIFReporter
    reporter = SARIFReporter()
    sarif_dict = reporter.generate(session, evidence_store)
    reporter.write(sarif_dict, "reports/scan123.sarif")
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

SEVERITY_TO_CVSS: Dict[str, float] = {
    "critical": 9.5,
    "high":     8.0,
    "medium":   5.5,
    "low":      3.0,
    "info":     0.0,
}

TOOL_NAME    = "zentry-trail"
TOOL_VERSION = "1.0.0"
TOOL_URI     = "https://github.com/zentry-trail/zentry-trail"


class SARIFReporter:
    """
    Generates SARIF 2.1.0 compliant output from scan findings.

    Each finding maps to one SARIF Result with:
      - ruleId:      vuln_class  (e.g. "xss", "sqli")
      - level:       "error" | "warning" | "note"
      - locations:   physicalLocation with the target URI
      - properties:  cvss_score, confirmed_payload, evidence_bundle_path
      - relatedLocations: for chain findings, references parent finding
    """

    def generate(
        self,
        session,
        evidence_store=None,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a SARIF 2.1.0 document.

        Parameters
        ----------
        session        : scan session object (has .findings, .target)
        evidence_store : optional EvidenceStore — adds bundle paths to properties
        scan_id        : override scan_id (defaults to session.scan_id or timestamp)
        """
        findings = getattr(session, "findings", []) or []
        target   = str(getattr(session, "target", ""))
        sid      = scan_id or getattr(session, "scan_id", None) or str(int(time.time()))

        rules   = self._build_rules(findings)
        results = self._build_results(findings, evidence_store)

        sarif = {
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
                        }
                    },
                    "results":  results,
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
        """Write SARIF document to disk and return the path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sarif, indent=2))
        return str(path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_finding_attr(self, finding, *keys):
        """Safely get an attribute from either a dict or object finding."""
        for key in keys:
            if isinstance(finding, dict):
                val = finding.get(key)
            else:
                val = getattr(finding, key, None)
            if val is not None:
                return val
        return None

    def _build_rules(self, findings: list) -> List[Dict]:
        """Deduplicate findings by vuln_class → one rule per class."""
        seen   = set()
        rules  = []
        for finding in findings:
            vuln_class = str(self._get_finding_attr(finding, "vuln_class", "vulnerability", "type") or "unknown")
            if vuln_class in seen:
                continue
            seen.add(vuln_class)
            severity   = str(self._get_finding_attr(finding, "severity") or "info").lower()
            cvss       = self._cvss_score(severity)
            rules.append({
                "id":   vuln_class,
                "name": vuln_class.upper().replace("_", " "),
                "shortDescription": {
                    "text": f"{vuln_class.upper()} vulnerability detected by zentry-trail"
                },
                "helpUri": TOOL_URI,
                "properties": {
                    "severity":   severity,
                    "cvss_score": cvss,
                    "tags":       ["security", vuln_class],
                },
                "defaultConfiguration": {
                    "level": SEVERITY_TO_LEVEL.get(severity, "warning")
                },
            })
        return rules

    def _build_results(self, findings: list, evidence_store) -> List[Dict]:
        """Map each finding to a SARIF result."""
        results = []
        for finding in findings:
            vuln_class = str(self._get_finding_attr(finding, "vuln_class", "vulnerability", "type") or "unknown")
            severity   = str(self._get_finding_attr(finding, "severity") or "info").lower()
            uri        = str(self._get_finding_attr(finding, "url", "uri", "endpoint") or "")
            summary    = str(self._get_finding_attr(finding, "summary", "description", "impact") or vuln_class)
            payload    = self._get_finding_attr(finding, "payload", "confirmed_payload") or ""
            finding_id = str(self._get_finding_attr(finding, "id", "finding_id") or "")
            parent_id  = self._get_finding_attr(finding, "parent_finding_id", "chain_parent_id")

            # Evidence bundle path from EvidenceStore
            bundle_path = ""
            if evidence_store and finding_id:
                try:
                    bundle_dir = Path(evidence_store.output_dir) / finding_id / "bundle.json"
                    if bundle_dir.exists():
                        bundle_path = str(bundle_dir)
                except Exception:
                    pass

            result: Dict[str, Any] = {
                "ruleId":  vuln_class,
                "level":   SEVERITY_TO_LEVEL.get(severity, "warning"),
                "message": {"text": summary},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region":           {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "cvss_score":          self._cvss_score(severity),
                    "severity":            severity,
                    "confirmed_payload":   str(payload),
                    "evidence_bundle_path": bundle_path,
                },
            }

            # relatedLocations: chain findings reference parent
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

    def _cvss_score(self, severity: str) -> float:
        return SEVERITY_TO_CVSS.get(severity.lower(), 0.0)
