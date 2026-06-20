"""
Business Logic Validator — Session 4

Evaluates multi-step workflows to identify complex logic flaws such as
state machine deviations, step skipping, and numerical parameter tampering.
"""

import aiohttp
from typing import Any, Dict, Optional

from modules.pipeline.engine.models import Evidence, ValidationResult
from modules.pipeline.validation.registry import register
from core.behavioral_baseline import BSMRecorder
from core.behavioral_probe import BSMDeviationProber

@register("biz_logic_validator")
class BizLogicValidator:
    validator_id = "biz_logic_validator"
    priority = 85
    SIGNALS = {
        "endpoint_patterns": ["/checkout", "/cart", "/order", "/payment", "/transfer", "/redeem"]
    }

    def __init__(self, context=None):
        self.context = context
        self.recorder = BSMRecorder()
        self.prober = BSMDeviationProber()

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = state.get("endpoints", [])
        for ep in endpoints:
            ep_lower = str(ep).lower()
            if any(pattern in ep_lower for pattern in self.SIGNALS["endpoint_patterns"]):
                return True
        return False

    async def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        endpoints = state.get("endpoints", [])
        if not endpoints:
            return None

        bsms = self.recorder.record_from_endpoints(endpoints, state)
        all_probes = []
        for bsm in bsms:
            all_probes.extend(self.prober.generate_probes(bsm, state))

        if not all_probes:
            return None

        timeout_val = state.get("timeout")
        timeout = aiohttp.ClientTimeout(total=int(timeout_val) if timeout_val else 10)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for probe in all_probes:
                    kwargs = {"allow_redirects": False}
                    if probe.method.upper() in ("POST", "PUT", "PATCH"):
                        kwargs["data"] = probe.modified_params
                    else:
                        kwargs["params"] = probe.modified_params

                    headers = {"User-Agent": "security-pipeline/1.0"}
                    cookies = dict(probe.baseline_step.session_cookies)

                    if probe.probe_type == "role_confusion" and state.get("alt_user_cookies"):
                        cookies = state.get("alt_user_cookies")

                    if cookies:
                        kwargs["cookies"] = cookies

                    try:
                        async with session.request(probe.method, probe.target_url, headers=headers, **kwargs) as resp:
                            if resp.status == 200 and probe.expected_rejection_status in (400, 403, 302):
                                severity_map = {"price_tamper": "critical", "step_skip": "high", "idor": "high", "role_confusion": "high", "csrf_bypass": "medium"}
                                return ValidationResult(success=True, confidence=0.9, severity=severity_map.get(probe.probe_type, "medium"), vulnerability=f"biz-logic-{probe.probe_type.replace('_', '-')}", evidence=Evidence(request={"url": probe.target_url, "method": probe.method, "params": probe.modified_params}, response={"status": resp.status, "expected_rejection": probe.expected_rejection_status}, matched="Expected rejection bypassed; received 200 OK"), impact=f"Business logic flow validation failure: {probe.description}", remediation="Implement strict state transition validation and verify all boundary conditions server-side.")
                    except Exception as e:
                        pass
        except Exception as e:
            pass
        return None