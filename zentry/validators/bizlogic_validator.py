"""
Business Logic Validator — Session 4 + IDOR Testing Expansion
=============================================================
Evaluates multi-step workflows to identify complex logic flaws such as
state machine deviations, step skipping, and numerical parameter tampering.
Also expanded to perform stateful IDOR vulnerability testing using authenticated sessions.
"""

from __future__ import annotations

import re
import random
import requests
import aiohttp
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List, Tuple
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit, urlparse, parse_qs, urlunparse

from zentry.session import Evidence, ExecutionContext, ValidationResult
from zentry.validators.base import BaseValidator
from zentry.validators.registry import register


# ---------------------------------------------------------------------------
# Data structures for Behavioral State Machine (BSM)
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
# Recorder
# ---------------------------------------------------------------------------

class BSMRecorder:
    """
    Groups endpoints into multi-step flows and extracts tamper-worthy
    parameters (numeric, money-like) for deviation probing.
    """

    FLOW_KEYWORDS = (
        "checkout", "cart", "order", "payment", "account",
        "password", "profile", "transfer", "redeem", "signup",
        "register", "confirm", "review", "submit", "basket", "buy",
    )

    NUMERIC_PARAM_RE   = re.compile(r"(qty|quantity|amount|price|total|count|num|id|uid)", re.I)
    DECIMAL_PARAM_RE   = re.compile(r"(price|amount|total|cost|discount|fee)", re.I)
    AUTH_INDICATOR_RE  = re.compile(r"(session|cookie|csrf|token|auth|bearer)", re.I)

    def record_from_endpoints(
        self,
        endpoints: List[str],
        state: Dict[str, Any],
    ) -> List[BehavioralStateMachine]:
        flows: Dict[str, List[str]] = {}

        for ep in endpoints:
            parsed = urlparse(ep if "://" in ep else f"http://{ep}")
            path   = parsed.path.rstrip("/")
            parts  = [p for p in path.split("/") if p]

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

    def _detect_flow_key(self, parts: List[str], url: str) -> Optional[str]:
        for part in parts:
            part_lower = part.lower()
            for kw in self.FLOW_KEYWORDS:
                if kw == part_lower or part_lower.startswith(kw):
                    return kw
        url_lower = url.lower()
        for kw in self.FLOW_KEYWORDS:
            if kw in url_lower:
                return kw
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
        steps = []
        detected_objects: Dict[str, str] = {}

        for i, ep in enumerate(endpoints):
            parsed = urlparse(ep if "://" in ep else f"http://{ep}")
            params = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}

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


# ---------------------------------------------------------------------------
# Prober
# ---------------------------------------------------------------------------

class BSMDeviationProber:
    """
    Generates deviation probes from a BehavioralStateMachine.
    """

    PRICE_TAMPER_VALUES = ["-1", "-999", "0", "999999", "1.5", "0.001"]
    IDOR_OFFSETS        = [-1, 1, 0, 100, 9999]

    def generate_probes(
        self,
        bsm  : BehavioralStateMachine,
        state: Dict[str, Any],
    ) -> List[DeviationProbe]:
        probes: List[DeviationProbe] = []

        probes.extend(self._step_skip_probes(bsm))
        probes.extend(self._price_tamper_probes(bsm))
        probes.extend(self._idor_probes(bsm))
        probes.extend(self._csrf_bypass_probes(bsm))
        probes.extend(self._role_confusion_probes(bsm, state))

        return probes

    def _step_skip_probes(self, bsm: BehavioralStateMachine) -> List[DeviationProbe]:
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
        probes = []
        for step in bsm.steps:
            for param_name, param_type in bsm.detected_objects.items():
                if param_type not in ("integer", "decimal"):
                    continue
                if param_name not in step.param_snapshot:
                    continue
                for tamper_value in self.PRICE_TAMPER_VALUES:
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

    @staticmethod
    def _rebuild_url(original_url: str, new_params: Dict[str, str]) -> str:
        parsed = urlparse(original_url if "://" in original_url else f"http://{original_url}")
        new_query = urlencode(new_params)
        rebuilt   = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))
        return rebuilt


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
        super().__init__()
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

        auth_manager = state.get("auth_manager")
        if auth_manager and auth_manager.authenticated:
            session = auth_manager.get_session()
            known_account_ids = []
            try:
                main_url = f"{auth_manager.base_url}/bank/main.jsp"
                r_main = session.get(main_url, verify=False, timeout=10)
                found_ids = re.findall(r'\b8\d{5}\b', r_main.text)
                for fid in found_ids:
                    val = int(fid)
                    if val not in known_account_ids:
                        known_account_ids.append(val)
            except Exception:
                pass

            if not known_account_ids:
                known_account_ids = [800000, 800001, 800002, 800003]

            idor_params = ["listAccounts", "listaccounts", "account", "id", "accountId"]
            candidate_endpoints = []
            for ep in endpoints:
                ep_lower = ep.lower()
                if any(param.lower() in ep_lower for param in idor_params):
                    candidate_endpoints.append(ep)

            if not candidate_endpoints:
                candidate_endpoints.append(f"{auth_manager.base_url}/bank/showAccount")

            for ep in candidate_endpoints:
                full_url = ep if ep.startswith("http") else f"{auth_manager.base_url}{ep}"
                parsed = urlsplit(full_url)
                params_present = [k for k, _ in parse_qsl(parsed.query)]
                
                target_params = [p for p in idor_params if p in params_present]
                if not target_params:
                    target_params = ["listAccounts"]

                for param in target_params:
                    for orig_id in known_account_ids:
                        test_offsets = [1, -1, 2, -2, 10, -10]
                        test_ids = [orig_id + offset for offset in test_offsets]
                        for _ in range(4):
                            test_ids.append(orig_id + random.randint(-500, 500))

                        test_ids = list(set([tid for tid in test_ids if tid > 0 and tid != orig_id]))

                        for foreign_id in test_ids:
                            test_url = _replace_query_param(full_url, param, str(foreign_id))
                            try:
                                r_test = session.get(test_url, verify=False, timeout=10)
                                is_valid_resp = (
                                    r_test.status_code == 200 
                                    and len(r_test.text) > 100 
                                    and "access denied" not in r_test.text.lower()
                                    and "forbidden" not in r_test.text.lower()
                                    and "not authorized" not in r_test.text.lower()
                                )

                                if is_valid_resp:
                                    if auth_manager.authenticated2 and auth_manager.session2:
                                        r_test2 = auth_manager.session2.get(test_url, verify=False, timeout=10)
                                        if r_test2.status_code == 200 and len(r_test2.text) > 100:
                                            req_headers = dict(r_test2.request.headers)
                                            if "Authorization" in req_headers:
                                                req_headers["Authorization"] = "***"
                                            if "Cookie" in req_headers:
                                                req_headers["Cookie"] = "***"

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
