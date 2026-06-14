"""
core/behavioral_baseline.py — Session 4

Behavioral State Machine (BSM) recorder for business logic flaw detection.

Records normal multi-step application flows during recon, then hands them
to BSMDeviationProber to generate tampered probe sequences that test for:
  - Workflow step skipping
  - Price / quantity tampering
  - Horizontal IDOR via adjacent IDs
  - CSRF token removal
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BSMStep:
    """One HTTP request within a recorded multi-step flow."""
    url:              str
    method:           str
    param_snapshot:   Dict[str, str]   # {name: value} at this step
    response_status:  int
    response_time_ms: int
    session_cookies:  Dict[str, str]
    step_index:       int


@dataclass
class BehavioralStateMachine:
    """A multi-step user workflow inferred from endpoint patterns."""
    flow_name:        str
    steps:            List[BSMStep]
    total_steps:      int
    requires_auth:    bool
    detected_objects: Dict[str, str]   # {param_name: "integer"|"decimal"|"string"}

    @property
    def is_multi_step(self) -> bool:
        return self.total_steps >= 3


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------

class BSMRecorder:
    """
    Groups endpoints into multi-step flows and extracts tamper-worthy
    parameters (numeric, money-like) for deviation probing.
    """

    # URL path keywords that indicate flow membership
    FLOW_KEYWORDS = (
        "checkout", "cart", "order", "payment", "account",
        "password", "profile", "transfer", "redeem", "signup",
        "register", "confirm", "review", "submit", "basket", "buy",
    )

    # Parameter name patterns that hold numeric / money values
    NUMERIC_PARAM_RE   = re.compile(r"(qty|quantity|amount|price|total|count|num|id|uid)", re.I)
    DECIMAL_PARAM_RE   = re.compile(r"(price|amount|total|cost|discount|fee)", re.I)
    AUTH_INDICATOR_RE  = re.compile(r"(session|cookie|csrf|token|auth|bearer)", re.I)

    def record_from_endpoints(
        self,
        endpoints: List[str],
        state: Dict[str, Any],
    ) -> List[BehavioralStateMachine]:
        """
        Group endpoints by URL prefix similarity into flows.
        Returns only flows with 2+ related steps.
        """
        flows: Dict[str, List[str]] = {}

        for ep in endpoints:
            parsed = urlparse(ep if "://" in ep else f"http://{ep}")
            path   = parsed.path.rstrip("/")
            parts  = [p for p in path.split("/") if p]

            # Map to a flow by the first non-trivial path segment
            flow_key = self._detect_flow_key(parts, ep)
            if flow_key:
                flows.setdefault(flow_key, []).append(ep)

        bsms: List[BehavioralStateMachine] = []
        for flow_name, flow_endpoints in flows.items():
            if len(flow_endpoints) < 2:
                continue
            bsm = self._build_bsm(flow_name, sorted(flow_endpoints), state)
            bsms.append(bsm)

        return bsms

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_flow_key(self, parts: List[str], url: str) -> Optional[str]:
        """Return the flow key for this URL based on first matching path segment."""
        # Check each path segment against FLOW_KEYWORDS — first match wins.
        # This groups /cart/checkout under 'cart', not 'checkout'.
        for part in parts:
            part_lower = part.lower()
            for kw in self.FLOW_KEYWORDS:
                if kw == part_lower or part_lower.startswith(kw):
                    return kw
        # Fallback: substring match in full URL
        url_lower = url.lower()
        for kw in self.FLOW_KEYWORDS:
            if kw in url_lower:
                return kw
        # Group by first non-trivial path segment
        for part in parts:
            if len(part) > 3 and not part.isdigit() and part not in ("api", "v1", "v2", "v3"):
                return part
        return None

    def _build_bsm(
        self,
        flow_name: str,
        endpoints: List[str],
        state: Dict[str, Any],
    ) -> BehavioralStateMachine:
        """Build a BSM from a list of related endpoints."""
        steps = []
        detected_objects: Dict[str, str] = {}

        for i, ep in enumerate(endpoints):
            parsed = urlparse(ep if "://" in ep else f"http://{ep}")
            params = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}

            # Detect object types
            for param_name, param_value in params.items():
                if self.DECIMAL_PARAM_RE.search(param_name):
                    detected_objects[param_name] = "decimal"
                elif self.NUMERIC_PARAM_RE.search(param_name):
                    detected_objects[param_name] = "integer"
                else:
                    detected_objects[param_name] = "string"

            step = BSMStep(
                url=ep,
                method="GET",
                param_snapshot=params,
                response_status=200,
                response_time_ms=100,
                session_cookies=dict(state.get("cookies") or {}),
                step_index=i,
            )
            steps.append(step)

        requires_auth = any(
            self.AUTH_INDICATOR_RE.search(k)
            for step in steps
            for k in step.session_cookies.keys()
        )

        return BehavioralStateMachine(
            flow_name=flow_name,
            steps=steps,
            total_steps=len(steps),
            requires_auth=requires_auth,
            detected_objects=detected_objects,
        )
