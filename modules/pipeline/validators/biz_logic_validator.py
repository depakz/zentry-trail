"""
Business Logic Validator — Session 4 + IDOR Testing Expansion
=============================================================
Evaluates multi-step workflows to identify complex logic flaws such as
state machine deviations, step skipping, and numerical parameter tampering.
Also expanded to perform stateful IDOR vulnerability testing using authenticated sessions.
"""

import aiohttp
import re
import random
import requests
from typing import Any, Dict, Optional, List
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

from modules.pipeline.engine.models import Evidence, ValidationResult
from modules.pipeline.validation.registry import register
from core.behavioral_baseline import BSMRecorder
from core.behavioral_probe import BSMDeviationProber
from modules.pipeline.validators.base import BaseValidator

def _replace_query_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out = []
    replaced = False
    for k, v in pairs:
        if k == key and not replaced:
            out.append((k, value))
            replaced = True
        elif k == key:
            continue
        else:
            out.append((k, v))
    if not replaced:
        out.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out, doseq=True), parts.fragment))

@register("biz_logic_validator")
class BizLogicValidator(BaseValidator):
    validator_id = "biz_logic_validator"
    priority = 85
    SIGNALS = {
        "endpoint_patterns": ["/checkout", "/cart", "/order", "/payment", "/transfer", "/redeem", "/bank"]
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

        # ── PART B: BizLogicValidator IDOR Testing ──────────────────────────────
        auth_manager = state.get("auth_manager")
        if auth_manager and auth_manager.authenticated:
            session = auth_manager.get_session()
            
            # Step 1 — DISCOVER account IDs from the authenticated response
            known_account_ids = []
            try:
                main_url = f"{auth_manager.base_url}/bank/main.jsp"
                r_main = session.get(main_url, verify=False, timeout=10)
                # Parse response HTML for account number patterns (regex: \b8\d{5}\b for Altoro-style IDs)
                found_ids = re.findall(r'\b8\d{5}\b', r_main.text)
                for fid in found_ids:
                    val = int(fid)
                    if val not in known_account_ids:
                        known_account_ids.append(val)
            except Exception:
                pass

            # Fallback if discovery failed but we want to be thorough
            if not known_account_ids:
                known_account_ids = [800000, 800001, 800002, 800003]

            # Step 2 — ENUMERATE adjacent IDs
            idor_params = ["listAccounts", "listaccounts", "account", "id", "accountId"]
            
            # Look for matching endpoints from signals or state endpoints
            candidate_endpoints = []
            for ep in endpoints:
                ep_lower = ep.lower()
                if any(param.lower() in ep_lower for param in idor_params):
                    candidate_endpoints.append(ep)

            # Ensure we test a baseline if no candidates found
            if not candidate_endpoints:
                candidate_endpoints.append(f"{auth_manager.base_url}/bank/showAccount")

            for ep in candidate_endpoints:
                full_url = ep if ep.startswith("http") else f"{auth_manager.base_url}{ep}"
                parsed = urlsplit(full_url)
                params_present = [k for k, _ in parse_qsl(parsed.query)]
                
                # Check target parameters
                target_params = [p for p in idor_params if p in params_present]
                if not target_params:
                    # If none present but endpoint matched, assume listAccounts or account as default
                    target_params = ["listAccounts"]

                for param in target_params:
                    for orig_id in known_account_ids:
                        # Enumerate adjacent IDs: ±1, ±2, ±10, plus some random
                        test_offsets = [1, -1, 2, -2, 10, -10]
                        test_ids = [orig_id + offset for offset in test_offsets]
                        # 3-5 random IDs in similar range
                        for _ in range(4):
                            test_ids.append(orig_id + random.randint(-500, 500))

                        # Clean duplicates & keep valid IDs
                        test_ids = list(set([tid for tid in test_ids if tid > 0 and tid != orig_id]))

                        for foreign_id in test_ids:
                            test_url = _replace_query_param(full_url, param, str(foreign_id))
                            try:
                                # Test original session (User A)
                                r_test = session.get(test_url, verify=False, timeout=10)
                                
                                # Step 3 — CONFIRM IDOR
                                # If response for foreign_id returns HTTP 200 AND response body differs from a baseline 403/empty response:
                                is_valid_resp = (
                                    r_test.status_code == 200 
                                    and len(r_test.text) > 100 
                                    and "access denied" not in r_test.text.lower()
                                    and "forbidden" not in r_test.text.lower()
                                    and "not authorized" not in r_test.text.lower()
                                )

                                if is_valid_resp:
                                    # Step 4 — DUAL SESSION TEST (for highest-confidence confirmation)
                                    if auth_manager.authenticated2 and auth_manager.session2:
                                        # Replay request using User B's session
                                        r_test2 = auth_manager.session2.get(test_url, verify=False, timeout=10)
                                        if r_test2.status_code == 200 and len(r_test2.text) > 100:
                                            # Mask credentials in evidence files/logs if any are present
                                            req_headers = dict(r_test2.request.headers)
                                            if "Authorization" in req_headers:
                                                req_headers["Authorization"] = "***"
                                            if "Cookie" in req_headers:
                                                # Mask session/auth cookies
                                                req_headers["Cookie"] = "***"

                                            # Confirmed cross-account IDOR, severity=critical
                                            return self.confirm_finding(
                                                request_obj=r_test2.request,
                                                response_obj=r_test2,
                                                vulnerability="idor-cross-account",
                                                severity="critical",
                                                confidence=0.98,
                                                param=param,
                                                payload=str(foreign_id),
                                                impact=f"Cross-account IDOR confirmed on parameter '{param}' using dual session test.",
                                                remediation="Ensure object-level access control is enforced on the server side."
                                            )
                                    
                                    # Single session IDOR confirmation
                                    return self.confirm_finding(
                                        request_obj=r_test.request,
                                        response_obj=r_test,
                                        vulnerability="idor",
                                        severity="high",
                                        confidence=0.9,
                                        param=param,
                                        payload=str(foreign_id),
                                        impact=f"IDOR detected on parameter '{param}'. Attacker can view foreign object ID {foreign_id}.",
                                        remediation="Implement strict object-level validation and ensure ownership verification is enforced."
                                    )
                            except Exception:
                                continue

        # Fallback to standard baseline deviations validation
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
                                return ValidationResult(
                                    success=True,
                                    confidence=0.9,
                                    severity=severity_map.get(probe.probe_type, "medium"),
                                    vulnerability=f"biz-logic-{probe.probe_type.replace('_', '-')}",
                                    evidence=Evidence(
                                        request={"url": probe.target_url, "method": probe.method, "params": probe.modified_params},
                                        response={"status": resp.status, "expected_rejection": probe.expected_rejection_status},
                                        matched="Expected rejection bypassed; received 200 OK"
                                    ),
                                    impact=f"Business logic flow validation failure: {probe.description}",
                                    remediation="Implement strict state transition validation and verify all boundary conditions server-side."
                                )
                    except Exception:
                        pass
        except Exception:
            pass
        return None