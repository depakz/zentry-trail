"""
Finding deduplication pipeline for the report generation layer.

Deduplicates findings by (target_url, vulnerability_type) using SHA-256
hashing as the uniqueness key. When duplicates are detected, the entry
with the higher CVSS score is kept (merging by max(cvss) and max(score)).
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List


def _dedup_key(finding: Dict[str, Any]) -> str:
    """
    Compute a SHA-256 uniqueness key from target_url + vulnerability type.

    Handles both report-payload dicts (keys: target_url, vulnerability)
    and Finding-like dicts (keys: endpoint, title).
    """
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
    """
    Compute a SHA-256 uniqueness key from a Finding dataclass instance.

    Falls back to _dedup_key for dict inputs.
    """
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
    """
    Deduplicate a raw list of finding dicts.

    Uniqueness key = SHA256(target_url + vulnerability_type).
    When a duplicate is detected, KEEP the entry with the higher CVSS
    score, merging by taking max(cvss) and max(score).

    Parameters
    ----------
    findings : list[dict]
        Raw list of finding dicts from all validators.
        Each dict has keys: target_url, vulnerability, cvss, score, ...

    Returns
    -------
    list[dict]
        Deduplicated list — no duplicate (url, vuln_type) pairs.
    """
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
                # Replace with the higher-scoring entry, keeping max of both
                merged = finding.copy()
                merged["cvss"] = max(current_cvss, existing_cvss)
                merged["score"] = max(current_score, existing_score)
                seen[key] = merged
            else:
                # Keep existing but ensure max(cvss) and max(score)
                existing["cvss"] = max(current_cvss, existing_cvss)
                existing["score"] = max(current_score, existing_score)

    return [seen[k] for k in insertion_order]


def dedup_finding_objects(findings: list) -> list:
    """
    Deduplicate a list of Finding dataclass instances.

    Works like dedup_findings but operates on Finding objects (with
    attributes like .endpoint, .title, .score) instead of plain dicts.

    When a duplicate is detected, KEEP the entry with the higher score.

    Parameters
    ----------
    findings : list
        List of Finding dataclass instances (or any objects with
        endpoint/title/score attributes).

    Returns
    -------
    list
        Deduplicated list of Finding objects.
    """
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
                # Replace with the higher-scoring Finding
                seen[key] = finding

    return [seen[k] for k in insertion_order]
