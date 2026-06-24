"""
zentry/session.py — ScanSession dataclass, Finding, FactStore, and related models.

This is the single source of truth for all session state, finding models,
and fact storage used across the zentry package.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Finding dataclass (used by Session and validators)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    endpoint: str = ""
    payload: str = ""
    evidence: str = ""
    validated: bool = False
    reproduction: list = field(default_factory=list)
    impact: str = ""
    cve: list = field(default_factory=list)
    score: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# FactStore — lightweight in-memory store for runtime facts/signals
# ──────────────────────────────────────────────────────────────────────────────

class FactCategory(enum.Enum):
    SERVICE_INFO = "service_info"
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"
    ENDPOINT = "endpoint"
    CREDENTIAL = "credential"
    TECHNOLOGY = "technology"
    MISC = "misc"


@dataclass
class Fact:
    category: FactCategory
    key: str
    value: Any = None
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


class FactStore:
    """In-memory fact store for scan session."""

    def __init__(self):
        self._facts: List[Fact] = []

    def add_fact(self, fact: Fact) -> None:
        self._facts.append(fact)

    def get_facts_by_category(self, category: FactCategory) -> List[Fact]:
        return [f for f in self._facts if f.category == category]

    def add_confirmed_vulnerability(
        self,
        vuln_id: str,
        vuln_type: str,
        target: str,
        confidence: float = 0.9,
        source_validator_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.add_fact(Fact(
            category=FactCategory.CONFIRMED_VULNERABILITY,
            key=vuln_id,
            value={
                "type": vuln_type,
                "target": target,
                "source_validator_id": source_validator_id,
                **(metadata or {}),
            },
            confidence=confidence,
            metadata=metadata or {},
        ))

    def get_all_facts(self) -> List[Fact]:
        return list(self._facts)


# ──────────────────────────────────────────────────────────────────────────────
# Evidence / ValidationResult models (from models.py consolidation)
# ──────────────────────────────────────────────────────────────────────────────

_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class ExecutionContext:
    target: str = ""
    endpoints: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    cookie: str = ""
    headers: Dict[str, Any] = field(default_factory=dict)
    session_context: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_state(cls, state: Dict[str, Any]) -> "ExecutionContext":
        if not isinstance(state, dict):
            return cls()

        target = str(state.get("target") or "")

        endpoints = state.get("endpoints") or []
        if not isinstance(endpoints, list):
            endpoints = []
        endpoints = [e for e in endpoints if isinstance(e, str)]

        findings = state.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        findings = [f for f in findings if isinstance(f, dict)]

        metadata = state.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        cookie = state.get("cookie") or ""
        if not isinstance(cookie, str):
            cookie = str(cookie)

        headers = state.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}

        session_context = state.get("session_context") or {}
        if not isinstance(session_context, dict):
            session_context = {}

        return cls(
            target=target,
            endpoints=endpoints,
            findings=findings,
            metadata=metadata,
            cookie=cookie,
            headers=headers,
            session_context=session_context,
        )


@dataclass
class Evidence:
    request: Any
    response: Any
    matched: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    """
    Enhanced evidence storage for high-confidence validation.

    Stores complete evidence of actual code execution, not just pattern matches.
    """
    raw_request: str
    raw_response: str
    matched_indicator: str
    execution_proof: Dict[str, Any] = field(default_factory=dict)
    tool_logs: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "matched_indicator": self.matched_indicator,
            "execution_proof": self.execution_proof,
            "tool_logs": self.tool_logs,
            "metadata": self.metadata,
        }


@dataclass
class ValidationResult:
    success: bool
    confidence: float
    severity: str
    vulnerability: str
    evidence: Evidence
    impact: str = ""
    remediation: str = ""
    confidence_score: float = 0.0
    evidence_bundle: Optional[EvidenceBundle] = None
    chain_source: Optional[str] = None
    execution_proved: bool = False
    validator_id: Optional[str] = None
    validator_class: Optional[str] = None

    def __post_init__(self):
        """Ensure confidence_score is synced with confidence if not explicitly set."""
        if self.confidence_score == 0.0:
            self.confidence_score = self.confidence

    def to_dict(self) -> Dict[str, Any]:
        severity = (self.severity or "info").strip().lower()
        if severity not in _ALLOWED_SEVERITIES:
            severity = "info"

        try:
            confidence = float(self.confidence)
        except Exception:
            confidence = 0.0

        if confidence < 0.0:
            confidence = 0.0
        if confidence > 1.0:
            confidence = 1.0

        try:
            confidence_score = float(self.confidence_score)
        except Exception:
            confidence_score = confidence

        if confidence_score < 0.0:
            confidence_score = 0.0
        if confidence_score > 1.0:
            confidence_score = 1.0

        result = {
            "success": bool(self.success),
            "vulnerability": self.vulnerability,
            "severity": severity,
            "validation": {
                "status": "confirmed" if self.success else "failed",
                "confidence": confidence,
                "confidence_score": confidence_score,
                "execution_proved": self.execution_proved,
            },
            "evidence": {
                "request": self.evidence.request,
                "response": self.evidence.response,
                "matched": self.evidence.matched,
                "extra": self.evidence.extra or {},
            },
            "impact": self.impact,
            "remediation": self.remediation,
        }

        if self.evidence_bundle is not None:
            result["evidence_bundle"] = self.evidence_bundle.to_dict()

        if self.chain_source is not None:
            result["chain_source"] = self.chain_source

        if self.validator_id is not None:
            result["validator_id"] = self.validator_id

        if self.validator_class is not None:
            result["validator_class"] = self.validator_class

        return result


# ──────────────────────────────────────────────────────────────────────────────
# ScanSession — the main session state container
# ──────────────────────────────────────────────────────────────────────────────

class ScanSession:
    """Scan session state container with JSON persistence."""

    def __init__(self, target: str, base_dir: str = "data/sessions"):
        # Sanitize target: strip protocol and replace special chars
        safe_target = re.sub(r'^https?://', '', target)
        safe_target = safe_target.rstrip('/')
        safe_target = re.sub(r'[^\w\-.]', '_', safe_target)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.id = str(uuid.uuid4())
        filename = f"session_{safe_target}_{timestamp}.json"

        # Ensure base directory exists
        os.makedirs(base_dir, exist_ok=True)

        self.path = os.path.join(base_dir, filename)
        self.target = target
        self.data: Dict[str, Any] = {"target": target, "created": timestamp}
        self.waf: Dict[str, Any] = {}
        self.subdomains: List[str] = []
        self.alive_hosts: List[Any] = []
        self.endpoints: List[str] = []
        self.nuclei_tags: List[str] = []
        self.findings: List[Any] = []
        self.save()

    def update(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.save()

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def get_all(self) -> Dict[str, Any]:
        return dict(self.data)

    def add_finding(self, finding: Any) -> None:
        if not hasattr(self, 'findings') or self.findings is None:
            self.findings = []
        self.findings.append(finding)

    def save(self) -> str:
        # Serialize dynamically added attributes
        for attr in ["subdomains", "alive_hosts", "endpoints", "waf", "nuclei_tags"]:
            if hasattr(self, attr):
                self.data[attr] = getattr(self, attr)
        if hasattr(self, "findings"):
            self.data["findings"] = [
                asdict(f) if hasattr(f, "__dataclass_fields__") else
                (f.to_dict() if hasattr(f, "to_dict") else f)
                for f in (self.findings or [])
            ]

        # Ensure parent directory exists before writing
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        return self.path


# Backward-compat aliases
Session = ScanSession
