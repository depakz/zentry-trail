"""API and Protocol validators (gRPC, GraphQL, etc.)."""

import json
import re
import socket
import subprocess
import logging
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

import requests

from zentry.session import Evidence, ValidationResult

logger = logging.getLogger("zentry.validators.api")


# =========================================================================
# gRPC Validator
# =========================================================================

class gRPCValidator:
    """Validator for gRPC security issues via grpcurl."""

    SIGNALS = {"endpoint_patterns": [":50051", ":50052", "grpc", ":9090"]}
    validator_id = "grpc_validator"
    priority = 75

    def __init__(self):
        self.destructive = False
        self._grpcurl_available = self._check_grpcurl()

    def _check_grpcurl(self) -> bool:
        """Check if grpcurl binary is available."""
        try:
            subprocess.run(["grpcurl", "-version"], capture_output=True, timeout=2)
            return True
        except Exception:
            return False

    def can_run(self, state: Dict[str, Any]) -> bool:
        if not self._grpcurl_available:
            return False

        endpoints = [str(x).lower() for x in (state.get("endpoints") or [])]
        endpoints += [str(x).lower() for x in (state.get("ports") or [])]

        return any(
            any(port in ep for port in ["50051", "50052", "9090", "16500", "3000"])
            or "grpc" in ep
            for ep in endpoints
        )

    def _probe_reflection(self, host: str, port: int) -> Optional[dict]:
        """Probe for gRPC reflection."""
        try:
            result = subprocess.run(
                ["grpcurl", "-plaintext", f"{host}:{port}", "list"],
                capture_output=True,
                timeout=5,
                text=True,
            )
            if result.returncode == 0 and result.stdout:
                services = [line.strip() for line in result.stdout.split("\n") if line.strip()]
                return {"services": services}
        except Exception as e:
            logger.debug(f"gRPC reflection probe failed: {e}")

        return None

    def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        """Probe target for gRPC vulnerabilities."""
        target_url = state.get("url") or state.get("target")
        if not target_url:
            endpoints = state.get("endpoints") or []
            if endpoints:
                target_url = endpoints[0]
        if not target_url:
            return None

        try:
            if "://" in target_url:
                host = target_url.split("://")[1].split(":")[0]
                port = int(target_url.split(":")[-1]) if ":" in target_url.split("://")[1] else 50051
            else:
                host = target_url.split(":")[0]
                port = int(target_url.split(":")[-1]) if ":" in target_url else 50051
        except Exception:
            return None

        # Test 1: Reflection detection
        reflection_data = self._probe_reflection(host, port)
        if reflection_data:
            services = reflection_data.get("services", [])
            logger.warning(f"gRPC: reflection enabled on {host}:{port}, exposing {len(services)} services")
            return ValidationResult(
                success=True,
                confidence=0.9,
                severity="high",
                vulnerability="grpc-reflection-enabled",
                evidence=Evidence(
                    request={"target": f"{host}:{port}", "method": "list"},
                    response={"services": services[:5]},
                    matched="reflection_enabled",
                ),
                impact="gRPC reflection exposes service definitions and method signatures, enabling targeted attacks.",
                remediation="Disable gRPC reflection in production or restrict it to authenticated clients.",
            )

        # Test 2: Unauthenticated method call attempt
        services_to_test = ["helloworld.Greeter"]
        if reflection_data and "services" in reflection_data:
            services_to_test = [s for s in reflection_data["services"] if "reflection" not in s.lower() and "health" not in s.lower()]
            
        for service in services_to_test:
            try:
                probe_result = subprocess.run(
                    ["grpcurl", "-plaintext", "-d", "{}", f"{host}:{port}", service],
                    capture_output=True,
                    timeout=3,
                    text=True,
                )
                stderr_lower = (probe_result.stderr or "").lower()
                if "unauthenticated" not in stderr_lower and "permissiondenied" not in stderr_lower:
                    if probe_result.returncode == 0 or "unimplemented" in stderr_lower:
                        return ValidationResult(
                            success=True,
                            confidence=0.85,
                            severity="high",
                            vulnerability="grpc-unauthenticated-access",
                            evidence=Evidence(
                                request={"target": f"{host}:{port}", "service": service},
                                response={"output": probe_result.stdout or probe_result.stderr},
                                matched="unauthenticated_method",
                            ),
                            impact="Unauthenticated gRPC methods are accessible from the network with empty or malformed payloads.",
                            remediation="Implement authentication and authorization checks for all gRPC methods.",
                        )
            except Exception as e:
                logger.debug(f"gRPC unauthenticated probe failed: {e}")

        return None


# =========================================================================
# GraphQL Validator & Schema Inference
# =========================================================================

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


HOPPER_WORDLIST = ["id", "name", "email", "password", "token", "admin", "user", "me"]

def infer_schema(api_url: str) -> Dict[str, Set[str]]:
    """Reconstruct schema by analyzing 'Did you mean X?' errors"""
    schema_map: Dict[str, Set[str]] = {}
    
    for base_field in HOPPER_WORDLIST:
        for type_hint in ["Query", "User", "Post"]:
            for alt in ["_id", "s", "1"]:
                query = f"""query {{ {base_field}{alt} {{ id }} }}"""
                try:
                    response = requests.post(api_url, json={"query": query}, timeout=5)
                    if response.status_code and "did you mean" in response.text.lower():
                        suggested_parts = response.text.lower().split("did you mean ")
                        if len(suggested_parts) > 1:
                            suggested = suggested_parts[1].split(".")[0].replace("?", "").replace('"', '').replace("'", "").strip()
                            if type_hint not in schema_map:
                                schema_map[type_hint] = set()
                            schema_map[type_hint].add(suggested)
                except Exception:
                    continue
    return schema_map

def brute_force_fields(api_url: str, schema_map: Dict[str, Set[str]], wordlist: List[str] = None) -> Dict[str, Dict[str, bool]]:
    """Test inferred schema against wordlist."""
    if wordlist is None:
        wordlist = HOPPER_WORDLIST
        
    results: Dict[str, Dict[str, bool]] = {}
    for obj_type, fields in schema_map.items():
        results[obj_type] = {}
        for field in wordlist:
            if field in fields:
                results[obj_type][field] = True
            else:
                query = f"""query {{ {obj_type.lower()} {{ {field} }} }}"""
                try:
                    response = requests.post(api_url, json={"query": query}, timeout=5)
                    if response.status_code == 200 and "data" in response.json():
                        results[obj_type][field] = True
                    else:
                        results[obj_type][field] = False
                except Exception:
                    results[obj_type][field] = False
    return results
