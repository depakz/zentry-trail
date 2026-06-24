"""
Evidence store with cryptographic signing for tamper evidence, and disk-based HTTP collector.
"""

import json
import time
import hashlib
import re
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("zentry.evidence")

# ── Constants ────────────────────────────────────────────────────────────────
MAX_SLUG_LENGTH = 80
MAX_RESPONSE_BODY_BYTES = 8192
MAX_RESPONSE_DISPLAY_BYTES = 2048  # For HTML report inline display
_SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie"}


@dataclass
class SignedRef:
    """Reference to a signed artifact."""
    s3_key: str
    content_hash: str
    signature: str
    signed_at: int
    artifact_type: str


class EvidenceStore:
    """Stores finding evidence with ECDSA signing."""

    def __init__(self, output_dir: str = "reports/evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.manifest: Dict[str, List[SignedRef]] = {}
        self.private_key, self.public_key = self._generate_session_key()

    def _generate_session_key(self) -> tuple:
        """Generate ECDSA P-256 key pair."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            return (private_key, public_key)
        except Exception:
            return (None, None)

    def store_artifact(self, finding_id: str, artifact_type: str, content: bytes) -> Optional[SignedRef]:
        """Store and sign an artifact."""
        content_hash = hashlib.sha256(content).hexdigest()

        finding_dir = self.output_dir / finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)

        artifact_path = finding_dir / f"{artifact_type}_{content_hash[:8]}"
        artifact_path.write_bytes(content)

        timestamp = int(time.time())
        signing_string = f"{content_hash}:{finding_id}:{artifact_type}:{timestamp}"
        
        sig_hex = ""
        if self.private_key:
            try:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                signature = self.private_key.sign(
                    signing_string.encode('utf-8'),
                    ec.ECDSA(hashes.SHA256())
                )
                sig_hex = signature.hex()
            except Exception:
                pass

        signed_ref = SignedRef(
            s3_key=str(artifact_path),
            content_hash=content_hash,
            signature=sig_hex,
            signed_at=timestamp,
            artifact_type=artifact_type,
        )

        if finding_id not in self.manifest:
            self.manifest[finding_id] = []
        self.manifest[finding_id].append(signed_ref)
        return signed_ref

    def store_http_pair(self, finding_id: str, request_dict: Dict, response_dict: Dict) -> tuple:
        """Store HTTP request/response pair."""
        req_content = json.dumps(request_dict).encode()
        resp_content = json.dumps(response_dict).encode()

        req_ref = self.store_artifact(finding_id, "http_request", req_content)
        resp_ref = self.store_artifact(finding_id, "http_response", resp_content)

        return (req_ref, resp_ref)

    def generate_bundle(self, finding_id: str) -> Dict:
        """Create verifiable evidence bundle for a finding including a Merkle root."""
        bundle_path = self.output_dir / finding_id / "bundle.json"
        
        finding_artifacts = self.manifest.get(finding_id, [])
        artifacts_data = [ref.__dict__ for ref in finding_artifacts]
        
        sorted_hashes = sorted([a["content_hash"] for a in artifacts_data])
        merkle_root = hashlib.sha256("".join(sorted_hashes).encode('utf-8')).hexdigest()
        
        bundle = {
            "finding_id": finding_id,
            "created_at": int(time.time()),
            "merkle_root": merkle_root,
            "artifacts": artifacts_data,
        }
        bundle_path.write_text(json.dumps(bundle, indent=2))
        return bundle

    def verify_bundle(self, finding_id: str) -> bool:
        """Verify all signatures in a bundle using the session public key."""
        bundle_path = self.output_dir / finding_id / "bundle.json"
        if not bundle_path.exists():
            return False
            
        try:
            bundle = json.loads(bundle_path.read_text())
            
            sorted_hashes = sorted([a["content_hash"] for a in bundle.get("artifacts", [])])
            expected_root = hashlib.sha256("".join(sorted_hashes).encode('utf-8')).hexdigest()
            if bundle.get("merkle_root") != expected_root:
                return False
                
            for art in bundle.get("artifacts", []):
                content_hash = art["content_hash"]
                artifact_type = art["artifact_type"]
                timestamp = art["signed_at"]
                sig_hex = art["signature"]
                s3_key = Path(art["s3_key"])

                if not s3_key.exists():
                    return False
                
                actual_content = s3_key.read_bytes()
                actual_hash = hashlib.sha256(actual_content).hexdigest()
                if actual_hash != content_hash:
                    return False

                signing_string = f"{content_hash}:{finding_id}:{artifact_type}:{timestamp}"
                
                if self.public_key and sig_hex:
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.asymmetric import ec
                    from cryptography.exceptions import InvalidSignature
                    try:
                        signature = bytes.fromhex(sig_hex)
                        self.public_key.verify(
                            signature,
                            signing_string.encode('utf-8'),
                            ec.ECDSA(hashes.SHA256())
                        )
                    except InvalidSignature:
                        return False
                    except Exception:
                        return False
            return True
        except Exception:
            return False


# ── Slug helpers ─────────────────────────────────────────────────────────────
def _slugify(text: str, max_len: int = MAX_SLUG_LENGTH) -> str:
    slug = str(text or "").lower()
    slug = re.sub(r"[^a-z0-9]", "_", slug)
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug[:max_len] if slug else "unknown"


def _endpoint_slug(url: str) -> str:
    try:
        path = urlparse(url).path or ""
    except Exception:
        path = str(url)
    return _slugify(path)


def _vuln_slug(vulnerability: str) -> str:
    return _slugify(vulnerability)


def _finding_filename(index: int, vuln: str, endpoint: str, suffix: str) -> str:
    vs = _vuln_slug(vuln)
    es = _endpoint_slug(endpoint)
    compound = f"{vs}_{es}"
    compound = re.sub(r"_+", "_", compound).strip("_")
    compound = compound[:MAX_SLUG_LENGTH]
    return f"finding_{index:02d}_{compound}_{suffix}.txt"


# ── Credential redaction ────────────────────────────────────────────────────
def _redact_header_value(name: str, value: str) -> str:
    if name.lower() in _SENSITIVE_HEADERS:
        return "[REDACTED]"
    return value


# ── Raw HTTP formatting from requests objects ────────────────────────────────
def format_request_from_prepared(prepared: Any) -> str:
    if prepared is None:
        return ""
    try:
        parsed = urlparse(prepared.url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        request_line = f"{prepared.method} {path} HTTP/1.1"
        headers = dict(prepared.headers or {})
        if "Host" not in headers and parsed.netloc:
            headers = {"Host": parsed.netloc, **headers}

        header_lines = [f"{k}: {_redact_header_value(k, v)}" for k, v in headers.items()]
        header_text = "\n".join(header_lines)

        body_text = ""
        if prepared.body:
            if isinstance(prepared.body, bytes):
                body_text = prepared.body.decode("utf-8", errors="replace")
            else:
                body_text = str(prepared.body)

        return f"{request_line}\n{header_text}\n\n{body_text}"
    except Exception as exc:
        logger.debug("Failed to format PreparedRequest: %s", exc)
        return ""


def format_response_from_response(response: Any) -> str:
    if response is None:
        return ""
    try:
        reason = response.reason or "OK"
        status_line = f"HTTP/1.1 {response.status_code} {reason}"

        header_lines = [
            f"{k}: {_redact_header_value(k, v)}"
            for k, v in response.headers.items()
        ]
        header_text = "\n".join(header_lines)

        body_text = ""
        if response.content is not None:
            raw_bytes = response.content[:MAX_RESPONSE_BODY_BYTES]
            body_text = raw_bytes.decode("utf-8", errors="replace")

        return f"{status_line}\n{header_text}\n\n{body_text}"
    except Exception as exc:
        logger.debug("Failed to format Response: %s", exc)
        return ""


# ── Legacy raw HTTP formatting from finding dicts ────────────────────────────
def format_raw_request(finding: Dict[str, Any]) -> str:
    if finding.get("raw_request"):
        return str(finding["raw_request"])

    url = str(finding.get("target_url") or finding.get("url") or finding.get("endpoint") or "")
    payload = str(finding.get("payload") or "")
    method = str(finding.get("method") or "GET").upper()

    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
    except Exception:
        host = ""
        path = url

    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {host}")
    lines.append("User-Agent: zentry-trail/1.0")

    if method == "POST" and payload:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(payload)}")

    evidence_headers = finding.get("_evidence_request_headers")
    if isinstance(evidence_headers, dict):
        for k, v in evidence_headers.items():
            if k.lower() not in ("host", "content-type", "content-length", "user-agent"):
                lines.append(f"{k}: {_redact_header_value(k, v)}")

    lines.append("")

    if method == "POST" and payload:
        lines.append(payload)
    elif method == "GET" and payload:
        lines.append(f"# Injected payload: {payload}")

    return "\n".join(lines)


def format_raw_response(finding: Dict[str, Any]) -> str:
    if finding.get("raw_response"):
        return str(finding["raw_response"])

    status = finding.get("_evidence_response_status") or 200
    snippet = str(finding.get("response_snippet") or finding.get("evidence") or "")

    lines = [f"HTTP/1.1 {status} OK"]

    resp_headers = finding.get("_evidence_response_headers")
    if isinstance(resp_headers, dict):
        for k, v in resp_headers.items():
            lines.append(f"{k}: {_redact_header_value(k, v)}")

    lines.append("")
    lines.append(snippet[:MAX_RESPONSE_BODY_BYTES])

    return "\n".join(lines)


# ── Evidence Collector ───────────────────────────────────────────────────────
class EvidenceCollector:
    """
    Writes raw HTTP evidence files to disk for confirmed findings.
    """

    def __init__(self, base_dir: str = "_output/evidence", scan_timestamp: Optional[str] = None):
        self.scan_timestamp = scan_timestamp or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.evidence_dir = Path(base_dir) / self.scan_timestamp
        self._created = False

    def _ensure_dir(self) -> bool:
        if self._created:
            return True
        try:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            self._created = True
            return True
        except Exception as exc:
            logger.warning("WARNING: evidence capture disabled — %s", exc)
            return False

    def save_single_evidence(
        self,
        index: int,
        vuln: str,
        endpoint: str,
        prepared_request: Optional[Any] = None,
        response_obj: Optional[Any] = None,
        raw_request_text: str = "",
        raw_response_text: str = "",
    ) -> Dict[str, str]:
        if not self._ensure_dir():
            return {"evidence_req_path": "", "evidence_res_path": ""}

        req_filename = _finding_filename(index, vuln, endpoint, "req")
        res_filename = _finding_filename(index, vuln, endpoint, "res")

        req_path = self.evidence_dir / req_filename
        res_path = self.evidence_dir / res_filename

        req_content = ""
        if prepared_request is not None:
            req_content = format_request_from_prepared(prepared_request)
        if not req_content:
            req_content = raw_request_text

        res_content = ""
        if response_obj is not None:
            res_content = format_response_from_response(response_obj)
        if not res_content:
            res_content = raw_response_text

        try:
            req_path.write_text(req_content, encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to write evidence request for finding %d: %s", index, exc)
            req_path = None

        try:
            res_path.write_text(res_content, encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to write evidence response for finding %d: %s", index, exc)
            res_path = None

        result = {}
        try:
            result["evidence_req_path"] = str(req_path.relative_to(Path.cwd())) if req_path and req_path.exists() else ""
        except ValueError:
            result["evidence_req_path"] = str(req_path) if req_path and req_path.exists() else ""
        try:
            result["evidence_res_path"] = str(res_path.relative_to(Path.cwd())) if res_path and res_path.exists() else ""
        except ValueError:
            result["evidence_res_path"] = str(res_path) if res_path and res_path.exists() else ""

        return result

    def save_evidence(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not findings:
            return findings

        if not self._ensure_dir():
            for finding in findings:
                finding.setdefault("evidence_req_path", "")
                finding.setdefault("evidence_res_path", "")
            return findings

        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue

            if finding.get("evidence_req_path") and finding.get("evidence_res_path"):
                continue

            vuln = str(finding.get("vulnerability") or finding.get("title") or "unknown")
            endpoint = str(finding.get("target_url") or finding.get("endpoint") or "unknown")

            req_filename = _finding_filename(index, vuln, endpoint, "req")
            res_filename = _finding_filename(index, vuln, endpoint, "res")

            req_path = self.evidence_dir / req_filename
            res_path = self.evidence_dir / res_filename

            try:
                req_content = format_raw_request(finding)
                req_path.write_text(req_content, encoding="utf-8")
            except Exception as exc:
                logger.warning("Failed to write evidence request for finding %d: %s", index, exc)
                req_path = None

            try:
                res_content = format_raw_response(finding)
                res_path.write_text(res_content, encoding="utf-8")
            except Exception as exc:
                logger.warning("Failed to write evidence response for finding %d: %s", index, exc)
                res_path = None

            try:
                finding["evidence_req_path"] = str(req_path.relative_to(Path.cwd())) if req_path and req_path.exists() else ""
            except ValueError:
                finding["evidence_req_path"] = str(req_path) if req_path and req_path.exists() else ""
            try:
                finding["evidence_res_path"] = str(res_path.relative_to(Path.cwd())) if res_path and res_path.exists() else ""
            except ValueError:
                finding["evidence_res_path"] = str(res_path) if res_path and res_path.exists() else ""

        return findings

    @property
    def directory(self) -> Path:
        return self.evidence_dir
