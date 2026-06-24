"""
zentry/reporting/dedup.py — Finding deduplication with SHA256 key + max CVSS.

Consolidated from core/orchestrator.py dedup logic.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict


def _dedup_key(finding: Dict[str, Any]) -> str:
    target_url = str(
        finding.get("target_url")
        or finding.get("endpoint")
        or finding.get("url")
        or ""
    )
    vulnerability = str(
        finding.get("vulnerability")
        or finding.get("title")
        or finding.get("vuln_class")
        or ""
    )
    raw = target_url + vulnerability
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _dedup_key_obj(finding_obj) -> str:
    if isinstance(finding_obj, dict):
        return _dedup_key(finding_obj)
    target_url = str(
        getattr(finding_obj, "target_url", None)
        or getattr(finding_obj, "endpoint", None)
        or getattr(finding_obj, "url", None)
        or ""
    )
    vulnerability = str(
        getattr(finding_obj, "vulnerability", None)
        or getattr(finding_obj, "title", None)
        or getattr(finding_obj, "vuln_class", None)
        or ""
    )
    raw = target_url + vulnerability
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def dedup_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate finding dicts using SHA256(url+vuln) as key, keeping max CVSS."""
    if not findings:
        return []

    seen: Dict[str, Dict[str, Any]] = {}
    insertion_order: list[str] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        key = _dedup_key(finding)
        current_cvss = float(finding.get("cvss") or 0.0)
        current_score = float(finding.get("score") or 0.0)

        if key not in seen:
            seen[key] = finding.copy()
            insertion_order.append(key)
        else:
            existing = seen[key]
            existing_cvss = float(existing.get("cvss") or 0.0)
            existing_score = float(existing.get("score") or 0.0)

            if current_cvss > existing_cvss:
                merged = finding.copy()
                merged["cvss"] = max(current_cvss, existing_cvss)
                merged["score"] = max(current_score, existing_score)
                seen[key] = merged
            else:
                existing["cvss"] = max(current_cvss, existing_cvss)
                existing["score"] = max(current_score, existing_score)

    return [seen[k] for k in insertion_order]


def dedup_finding_objects(findings: list) -> list:
    """Deduplicate finding objects (dataclasses / objects with attributes), keeping max score."""
    if not findings:
        return []

    seen: Dict[str, Any] = {}
    insertion_order: list[str] = []

    for finding in findings:
        key = _dedup_key_obj(finding)
        current_score = float(getattr(finding, "score", 0.0) or 0.0)

        if key not in seen:
            seen[key] = finding
            insertion_order.append(key)
        else:
            existing = seen[key]
            existing_score = float(getattr(existing, "score", 0.0) or 0.0)

            if current_score > existing_score:
                seen[key] = finding

    return [seen[k] for k in insertion_order]
