"""
zentry/chains/engine.py — Attack chain correlation engine.

Evaluates findings against chain rules to identify multi-step attack paths.
Consolidated from core/chain_synthesis.py and modules/pipeline/brain/dag_engine.py.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional


class ChainEngine:
    """
    Evaluates a list of findings against chain rules to discover
    confirmed multi-step attack chains.

    Usage:
        engine = ChainEngine(CHAIN_RULES)
        chains = engine.evaluate(findings)
    """

    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules or []

    def evaluate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Match findings against chain rules and return confirmed attack chains.

        Each rule specifies required vulnerability types. If all required types
        are present in the findings, the chain is confirmed.
        """
        if not findings or not self.rules:
            return []

        # Build a lookup: vuln_type -> list of findings
        vuln_map: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            if not isinstance(f, dict):
                continue
            vuln = str(
                f.get("vulnerability")
                or f.get("title")
                or f.get("type")
                or ""
            ).lower().strip()
            if vuln:
                vuln_map.setdefault(vuln, []).append(f)

        confirmed_chains: List[Dict[str, Any]] = []

        for rule in self.rules:
            if not isinstance(rule, dict):
                continue

            chain_id = rule.get("chain_id", "")
            required = rule.get("required_vulns", [])
            if not required:
                continue

            # Check if all required vuln types have at least one finding
            component_findings: List[Dict[str, Any]] = []
            all_matched = True

            for req_vuln in required:
                req_lower = str(req_vuln).lower().strip()
                matched = False

                # Exact match first
                if req_lower in vuln_map:
                    component_findings.append(vuln_map[req_lower][0])
                    matched = True
                else:
                    # Fuzzy match: check if the required vuln substring exists
                    for vuln_key, vuln_findings in vuln_map.items():
                        if req_lower in vuln_key or vuln_key in req_lower:
                            component_findings.append(vuln_findings[0])
                            matched = True
                            break

                if not matched:
                    all_matched = False
                    break

            if all_matched and component_findings:
                # Calculate aggregate severity and CVSS
                max_cvss = max(
                    float(f.get("cvss") or f.get("score") or 0.0)
                    for f in component_findings
                )
                # Chain CVSS bonus: multi-step chains are more severe
                chain_cvss = min(10.0, max_cvss + 0.5 * (len(component_findings) - 1))

                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                max_severity = max(
                    (str(f.get("severity") or "info").lower() for f in component_findings),
                    key=lambda s: severity_order.get(s, 0),
                )

                confirmed_chains.append({
                    "chain_id": chain_id,
                    "name": rule.get("name", chain_id),
                    "description": rule.get("description", ""),
                    "severity": max_severity,
                    "cvss": round(chain_cvss, 1),
                    "owasp": rule.get("owasp", ""),
                    "component_findings": component_findings,
                    "required_vulns": required,
                })

        return confirmed_chains

    def describe(self) -> Dict[str, Any]:
        """Return a summary of configured chain rules."""
        return {
            "total_rules": len(self.rules),
            "rules": [
                {
                    "chain_id": r.get("chain_id", ""),
                    "name": r.get("name", ""),
                    "required_vulns": r.get("required_vulns", []),
                }
                for r in self.rules
                if isinstance(r, dict)
            ],
        }
