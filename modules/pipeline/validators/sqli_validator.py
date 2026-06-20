"""Genetic Fallback Engine Validator for SQLi."""

import requests
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, parse_qsl, urlunsplit, urlencode

from modules.pipeline.engine.models import Evidence, ValidationResult
from core.genetic_engine import PayloadGeneticEngine
from core.diff_analyzer import DifferentialAnalyzer

def _replace_query_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    updated = []
    replaced = False
    for k, v in pairs:
        if k == key and not replaced:
            updated.append((k, value))
            replaced = True
        else:
            updated.append((k, v))
    if not replaced:
        updated.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated, doseq=True), parts.fragment))

class SQLiValidator:
    validator_id = "sqli_validator"
    priority = 85

    def __init__(self, context=None):
        self.context = context
        self.engine = PayloadGeneticEngine()

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        target_url = state.get("url") or state.get("target")
        if not target_url:
            return None

        params = state.get("injection_params", ["id", "q"])
        headers = {"User-Agent": "security-pipeline/1.0"}
        timeout = int(state.get("timeout", 8) or 8)
        
        try:
            for param in params:
                baseline_url = _replace_query_param(target_url, param, "safe_val")
                baseline_resp = requests.get(baseline_url, headers=headers, timeout=timeout)

                # Hooking genetic engine fallback into sqli_validator when metrics yield < 0.3 fitness.
                def sqli_evaluator(payload: str):
                    probe_url = _replace_query_param(target_url, param, payload)
                    probe_resp = requests.get(probe_url, headers=headers, timeout=timeout)
                    return DifferentialAnalyzer.analyze(baseline_resp, probe_resp)
                    
                best_payload, best_score = self.engine.evolve(
                    "SQLI", target_url, param, sqli_evaluator, baseline_resp, remaining_budget_seconds=30.0
                )
                
                if best_score >= 0.35:
                    return ValidationResult(
                        success=True, confidence=best_score, severity="high", vulnerability="sqli-genetic-evolved",
                        evidence=Evidence(request={"url": target_url, "param": param}, response={"fitness": best_score}, matched=best_payload),
                        impact="SQL injection found via genetic payload evolution.", remediation="Use parameterized queries."
                    )
        except Exception as e:
            pass
        return None