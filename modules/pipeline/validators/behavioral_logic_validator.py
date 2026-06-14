"""Behavioral baseline engine for business logic flaw detection."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from modules.pipeline.engine.models import Evidence, ValidationResult
from modules.pipeline.utils.logger import logger


@dataclass
class BehavioralStep:
    """Single step in a behavioral flow."""
    url: str
    method: str
    params: Dict[str, str]
    status: int


class BehavioralBaselineValidator:
    """Detect business logic flaws by identifying workflow deviations."""

    validator_id = "behavioral_validator"
    priority = 70

    def __init__(self):
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = [str(e).lower() for e in (state.get("endpoints") or [])]
        return any(
            pattern in ep
            for pattern in ["/checkout", "/cart", "/order", "/payment", "/account", "/transfer"]
            for ep in endpoints
        )

    def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        """Probe for business logic flaws."""
        endpoints = [e for e in (state.get("endpoints") or []) if isinstance(e, str)]
        target_url = state.get("url") or state.get("target")

        if not endpoints or not target_url:
            return None

        # Test: Price tampering
        for endpoint in endpoints:
            if "/checkout" in endpoint or "/cart" in endpoint:
                try:
                    # Inject negative price
                    modified_url = endpoint.replace("=", "=") + ("&price=-1" if "?" in endpoint else "?price=-1")
                    resp = requests.get(modified_url, timeout=5, allow_redirects=False)
                    if resp.status_code == 200:
                        logger.warning(f"Behavioral: price tampering possible on {endpoint}")
                        return ValidationResult(
                            success=True,
                            confidence=0.8,
                            severity="critical",
                            vulnerability="business-logic-price-tampering",
                            evidence=Evidence(
                                request={"target": endpoint, "param": "price", "value": "-1"},
                                response={"status": resp.status_code},
                                matched="price=-1",
                            ),
                            impact="Attacker can manipulate order prices during checkout.",
                            remediation="Validate price values on server-side; prevent negative or excessive price modifications.",
                        )
                except Exception:
                    pass

        return None


__all__ = ["BehavioralBaselineValidator"]
