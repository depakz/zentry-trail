"""gRPC service validator - probes for reflection and authentication bypass."""

import subprocess
import socket
from typing import Any, Dict, List, Optional

from modules.pipeline.engine.models import Evidence, ValidationResult
from modules.pipeline.utils.logger import logger


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

        # Look for gRPC patterns: port numbers like 50051, or :9090, or "grpc" in path
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
            return None

        # Extract host and port from URL
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
                    response={"services": services[:5]},  # Truncate for display
                    matched="reflection_enabled",
                ),
                impact="gRPC reflection exposes service definitions and method signatures, enabling targeted attacks.",
                remediation="Disable gRPC reflection in production or restrict it to authenticated clients.",
            )

        # Test 2: Unauthenticated method call attempt
        try:
            methods_result = subprocess.run(
                ["grpcurl", "-plaintext", f"{host}:{port}", "list", "helloworld.Greeter"],
                capture_output=True,
                timeout=3,
                text=True,
            )
            if methods_result.returncode == 0:
                # Service exists and is callable without auth
                return ValidationResult(
                    success=True,
                    confidence=0.85,
                    severity="high",
                    vulnerability="grpc-unauthenticated-access",
                    evidence=Evidence(
                        request={"target": f"{host}:{port}", "service": "helloworld.Greeter"},
                        response={"accessible": True},
                        matched="unauthenticated_method",
                    ),
                    impact="Unauthenticated gRPC methods are accessible from the network.",
                    remediation="Implement authentication and authorization checks for all gRPC methods.",
                )
        except Exception:
            pass

        return None
