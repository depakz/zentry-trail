from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import aiohttp

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

    async def _burst(self, endpoint: str, body: Dict[str, Any], headers: Dict[str, str], count: int, timeout: int) -> List[Dict[str, Any]]:
        barrier = asyncio.Barrier(count)
        timeout_obj = aiohttp.ClientTimeout(total=float(timeout))

        async with aiohttp.ClientSession(timeout=timeout_obj, headers=headers) as session:
            async def _one(idx: int):
                await barrier.wait()
                try:
                    async with session.post(endpoint, data=body, allow_redirects=False) as resp:
                        text = await resp.text()
                        return {"idx": idx, "status": resp.status, "body": text[:200]}
                except Exception as exc:
                    return {"idx": idx, "error": str(exc)}

            return await asyncio.gather(*[_one(i) for i in range(count)])

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
            responses = asyncio.run(self._burst(target, payload, headers, 20, timeout))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                responses = loop.run_until_complete(self._burst(target, payload, headers, 20, timeout))
            finally:
                loop.close()

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
