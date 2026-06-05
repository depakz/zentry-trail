import os
import hashlib
import json
import time
from typing import Dict, Optional

class EvidenceStore:
    """Stores evidence either to MinIO (if available) or local filesystem as fallback.
    Provides a simple hash-based signature when cryptography isn't available.
    """
    def __init__(self, out_dir: str = None, minio_client: Optional[object] = None):
        self.out_dir = out_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'evidence')
        os.makedirs(self.out_dir, exist_ok=True)
        self.minio_client = minio_client
        self.signer = None

    def _local_path(self, name: str) -> str:
        ts = int(time.time())
        fname = f"{ts}-{name}"
        return os.path.join(self.out_dir, fname)

    def _hash_signature(self, data: bytes) -> str:
        h = hashlib.sha256(data).hexdigest()
        return h

    def save_evidence(self, data: bytes, meta: Dict) -> Dict:
        """Save evidence and return metadata with location and signature.
        If a MinIO client is provided and usable, we'd upload; otherwise write locally.
        """
        name = meta.get('name', 'evidence.bin')
        # attempt MinIO if client provided
        if self.minio_client is not None:
            try:
                # expected minio client API: put_object(bucket_name, object_name, data, length)
                bucket = meta.get('bucket', 'evidence')
                object_name = meta.get('object_name', name)
                # ensure bucket exists - best-effort
                try:
                    self.minio_client.make_bucket(bucket)
                except Exception:
                    pass
                # put_object expects a stream or bytes IO and length
                try:
                    import io
                    stream = io.BytesIO(data)
                    self.minio_client.put_object(bucket, object_name, stream, len(data))
                    url = f"minio://{bucket}/{object_name}"
                    # sign if signer available
                    if self.signer:
                        try:
                            sig = self.signer.sign(data)
                            sig_repr = sig.hex()
                        except Exception:
                            sig_repr = self._hash_signature(data)
                    else:
                        sig_repr = self._hash_signature(data)
                    return {'location': url, 'signature': sig_repr}
                except TypeError:
                    # fallback if client expects bytes directly
                    self.minio_client.put_object(bucket, object_name, data, len(data))
                    url = f"minio://{bucket}/{object_name}"
                    sig = self._hash_signature(data)
                    return {'location': url, 'signature': sig}
            except Exception:
                # fall through to local
                pass
        # local fallback
        path = self._local_path(name)
        with open(path, 'wb') as f:
            f.write(data)
        if self.signer:
            try:
                sig = self.signer.sign(data)
                sig_repr = sig.hex()
            except Exception:
                sig_repr = self._hash_signature(data)
        else:
            sig_repr = self._hash_signature(data)
        return {'location': path, 'signature': sig_repr}

    def attach_signer(self, signer: object):
        """Attach an `EvidenceSigner` instance to sign uploads."""
        self.signer = signer
