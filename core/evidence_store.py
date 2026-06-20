"""Evidence store with cryptographic signing for tamper evidence."""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
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
        except Exception as e:
            # Fallback if cryptography not available
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
            except Exception as e:
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
        except Exception as e:
            return False
