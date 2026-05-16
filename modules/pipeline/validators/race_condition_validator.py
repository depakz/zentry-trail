from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
import threading

from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult


class RaceConditionValidator:
    SIGNALS = {
        "endpoint_patterns": [
            "/checkout",
            "/payment",
            "/coupon",
            "/redeem",
            "/transfer",
            "/vote",
            "/apply",
            "/claim",
        ]
    }
    validator_id = "race_condition_validator"
    priority = 80

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = [str(x).lower() for x in (state.get("endpoints") or [])]
        return any(
            marker in ep
            for ep in endpoints
            for marker in ["checkout", "payment", "coupon", "redeem", "transfer", "vote", "apply", "claim"]
        )

    def _burst_sync(self, endpoint: str, body: Dict[str, Any], headers: Dict[str, str], count: int, timeout: int) -> List[Dict[str, Any]]:
        barrier = threading.Barrier(count)
        results: List[Dict[str, Any]] = []

        def worker(idx: int) -> None:
            try:
                barrier.wait()
            except Exception:
                pass
            try:
                resp = requests.post(endpoint, data=body, headers=headers, timeout=timeout, allow_redirects=False)
                text = resp.text or ""
                results.append({"idx": idx, "status": resp.status_code, "body": text[:200]})
            except Exception as exc:
                results.append({"idx": idx, "error": str(exc)})

        threads: List[threading.Thread] = []
        for i in range(count):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout + 5)

        return results

    def run(self, state: Dict[str, Any]):
        endpoints = [ep for ep in (state.get("endpoints") or []) if isinstance(ep, str)]
        candidates = [
            ep
            for ep in endpoints
            if any(m in ep.lower() for m in ["checkout", "payment", "coupon", "redeem", "transfer", "vote", "apply", "claim"])
        ]
        if not candidates:
            return None

        target = candidates[0]
        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        timeout = int(state.get("timeout", 8) or 8)
        payload = state.get("race_payload") if isinstance(state.get("race_payload"), dict) else {"amount": "1", "coupon": "SINGLE_USE"}

        try:
            responses = self._burst_sync(target, payload, headers, 20, timeout)
        except Exception:
            responses = []

        success_responses = [r for r in responses if r.get("status") in {200, 201, 202}]
        confirmed = len(success_responses) > 1

        if confirmed:
            store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()
            store.add_confirmed_vulnerability(
                vuln_id="race_condition_confirmed",
                vuln_type="race_condition_confirmed",
                target=target,
                source_validator_id=self.validator_id,
                metadata={"success_count": len(success_responses)},
            )
            return ValidationResult(
                success=True,
                confidence=0.94,
                severity="high",
                vulnerability="race-condition",
                evidence=Evidence(
                    request={"target": target, "parallel_requests": 20},
                    response={"success_count": len(success_responses), "sample": success_responses[:3]},
                    matched="multiple_success_for_single_use_action",
                ),
                impact="Concurrent requests bypassed single-use or atomicity controls, indicating race condition risk.",
                remediation="Use server-side locking, idempotency keys, and atomic transaction boundaries for state-changing operations.",
            )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="race-condition",
            evidence=Evidence(request={"target": target}, response={"responses": responses[:5]}, matched=""),
        )
