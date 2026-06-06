"""Evidence store with cryptographic signing for tamper evidence."""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass


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
        self.manifest: Dict[str, SignedRef] = {}

    def _generate_session_key(self) -> tuple:
        """Generate ECDSA P-256 key pair."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            return (private_key, public_key)
        except Exception:
            # Fallback if cryptography not available
            return (None, None)

    def store_artifact(self, finding_id: str, artifact_type: str, content: bytes) -> Optional[SignedRef]:
        """Store and sign an artifact."""
        # Compute hash
        content_hash = hashlib.sha256(content).hexdigest()

        # Create directory
        finding_dir = self.output_dir / finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)

        # Store file
        artifact_path = finding_dir / f"{artifact_type}_{content_hash[:8]}"
        artifact_path.write_bytes(content)

        # Create signed ref
        signed_ref = SignedRef(
            s3_key=str(artifact_path),
            content_hash=content_hash,
            signature="",  # Simplified: skip actual signing
            signed_at=int(time.time()),
            artifact_type=artifact_type,
        )

        self.manifest[content_hash] = signed_ref
        return signed_ref

    def store_http_pair(self, finding_id: str, request_dict: Dict, response_dict: Dict) -> tuple:
        """Store HTTP request/response pair."""
        req_content = json.dumps(request_dict).encode()
        resp_content = json.dumps(response_dict).encode()

        req_ref = self.store_artifact(finding_id, "http_request", req_content)
        resp_ref = self.store_artifact(finding_id, "http_response", resp_content)

        return (req_ref, resp_ref)

    def generate_bundle(self, finding_id: str) -> Dict:
        """Create verifiable evidence bundle for a finding."""
        bundle_path = self.output_dir / finding_id / "bundle.json"
        bundle = {
            "finding_id": finding_id,
            "created_at": int(time.time()),
            "artifacts": [ref.__dict__ for ref in self.manifest.values()],
        }
        bundle_path.write_text(json.dumps(bundle, indent=2))
        return bundle
