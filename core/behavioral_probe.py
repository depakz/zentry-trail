"""
core/behavioral_probe.py — Session 4

Generates deviation probes from a BehavioralStateMachine to test for:
  - Workflow step skipping   (jump from step N to step N+2)
  - Price / quantity tamper  (negative, zero, fractional, very large values)
  - Horizontal IDOR          (current_id ± 1)
  - CSRF token removal       (replay step without X-CSRF-Token)
  - Role confusion           (swap session cookies between user roles)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.behavioral_baseline import BehavioralStateMachine, BSMStep


# ---------------------------------------------------------------------------
# Probe dataclass
# ---------------------------------------------------------------------------

@dataclass
class DeviationProbe:
    """A single tampered HTTP request to fire against the target."""
    probe_type:               str        # "step_skip"|"price_tamper"|"idor"|"csrf_bypass"|"role_confusion"
    target_url:               str
    method:                   str
    modified_params:          Dict[str, str]
    baseline_step:            BSMStep
    expected_rejection_status: int       # 403, 400, or 302 — if we get 200 it's a finding
    description:              str = ""


# ---------------------------------------------------------------------------
# Prober
# ---------------------------------------------------------------------------

class BSMDeviationProber:
    """
    Generates deviation probes from a BehavioralStateMachine.

    Call generate_probes(bsm, state) to get a list of DeviationProbe objects
    ready to be fired as HTTP requests.
    """

    # Tamper values for price/quantity parameters
    PRICE_TAMPER_VALUES = ["-1", "-999", "0", "999999", "1.5", "0.001"]
    # Adjacent IDs for horizontal IDOR
    IDOR_OFFSETS        = [-1, 1, 0, 100, 9999]

    def generate_probes(
        self,
        bsm  : BehavioralStateMachine,
        state: Dict[str, Any],
    ) -> List[DeviationProbe]:
        """Generate all applicable probe types for a BSM."""
        probes: List[DeviationProbe] = []

        probes.extend(self._step_skip_probes(bsm))
        probes.extend(self._price_tamper_probes(bsm))
        probes.extend(self._idor_probes(bsm))
        probes.extend(self._csrf_bypass_probes(bsm))
        probes.extend(self._role_confusion_probes(bsm, state))

        return probes

    # ------------------------------------------------------------------
    # Probe generators
    # ------------------------------------------------------------------

    def _step_skip_probes(self, bsm: BehavioralStateMachine) -> List[DeviationProbe]:
        """Jump from step N directly to step N+2, skipping intermediate step."""
        probes = []
        steps  = bsm.steps
        for i in range(len(steps) - 2):
            skip_target = steps[i + 2]
            probes.append(DeviationProbe(
                probe_type="step_skip",
                target_url=skip_target.url,
                method=skip_target.method,
                modified_params=dict(skip_target.param_snapshot),
                baseline_step=steps[i],
                expected_rejection_status=302,
                description=f"Skip step {i} → step {i+2} in flow '{bsm.flow_name}'",
            ))
        return probes

    def _price_tamper_probes(self, bsm: BehavioralStateMachine) -> List[DeviationProbe]:
        """Tamper numeric/decimal parameters with boundary and negative values."""
        probes = []
        for step in bsm.steps:
            for param_name, param_type in bsm.detected_objects.items():
                if param_type not in ("integer", "decimal"):
                    continue
                if param_name not in step.param_snapshot:
                    continue
                for tamper_value in self.PRICE_TAMPER_VALUES:
                    if param_type == "integer" and "." in tamper_value and tamper_value != "0":
                        pass  # include fractional for integer params too (tests boundary)
                    modified = dict(step.param_snapshot)
                    modified[param_name] = tamper_value
                    probes.append(DeviationProbe(
                        probe_type="price_tamper",
                        target_url=self._rebuild_url(step.url, modified),
                        method=step.method,
                        modified_params=modified,
                        baseline_step=step,
                        expected_rejection_status=400,
                        description=f"Tamper {param_name}={tamper_value!r} in step {step.step_index}",
                    ))
        return probes

    def _idor_probes(self, bsm: BehavioralStateMachine) -> List[DeviationProbe]:
        """Probe adjacent IDs for horizontal IDOR."""
        probes = []
        for step in bsm.steps:
            for param_name, param_type in bsm.detected_objects.items():
                if param_type != "integer":
                    continue
                if "id" not in param_name.lower():
                    continue
                if param_name not in step.param_snapshot:
                    continue
                try:
                    base_id = int(step.param_snapshot[param_name])
                except (ValueError, TypeError):
                    continue
                for offset in self.IDOR_OFFSETS:
                    adjacent = base_id + offset
                    if adjacent <= 0:
                        continue
                    modified = dict(step.param_snapshot)
                    modified[param_name] = str(adjacent)
                    probes.append(DeviationProbe(
                        probe_type="idor",
                        target_url=self._rebuild_url(step.url, modified),
                        method=step.method,
                        modified_params=modified,
                        baseline_step=step,
                        expected_rejection_status=403,
                        description=f"IDOR: {param_name}={adjacent} (base={base_id})",
                    ))
        return probes

    def _csrf_bypass_probes(self, bsm: BehavioralStateMachine) -> List[DeviationProbe]:
        """Replay steps without X-CSRF-Token header."""
        probes = []
        for step in bsm.steps:
            modified = dict(step.param_snapshot)
            modified.pop("csrf_token", None)
            modified.pop("_token",     None)
            modified.pop("csrftoken",  None)
            probes.append(DeviationProbe(
                probe_type="csrf_bypass",
                target_url=step.url,
                method=step.method,
                modified_params=modified,
                baseline_step=step,
                expected_rejection_status=403,
                description=f"CSRF bypass: replay step {step.step_index} without token",
            ))
        return probes

    def _role_confusion_probes(
        self,
        bsm  : BehavioralStateMachine,
        state: Dict[str, Any],
    ) -> List[DeviationProbe]:
        """Swap session cookies between roles if two are provided in state."""
        alt_cookies: Optional[Dict] = state.get("alt_user_cookies")
        if not alt_cookies:
            return []
        probes = []
        for step in bsm.steps:
            probes.append(DeviationProbe(
                probe_type="role_confusion",
                target_url=step.url,
                method=step.method,
                modified_params=dict(step.param_snapshot),
                baseline_step=step,
                expected_rejection_status=403,
                description=f"Role confusion: use alt-role cookies at step {step.step_index}",
            ))
        return probes

    # ------------------------------------------------------------------
    # URL rebuilding
    # ------------------------------------------------------------------

    @staticmethod
    def _rebuild_url(original_url: str, new_params: Dict[str, str]) -> str:
        """Replace query string parameters in a URL."""
        parsed = urlparse(original_url if "://" in original_url else f"http://{original_url}")
        new_query = urlencode(new_params)
        rebuilt   = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))
        return rebuilt
