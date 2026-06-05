from typing import Tuple, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

class EvidenceSigner:
    def __init__(self, private_key_pem: Optional[bytes] = None):
        if not HAS_CRYPTO:
            raise RuntimeError('cryptography not available')
        if private_key_pem is None:
            # generate new key
            self._priv = ec.generate_private_key(ec.SECP256R1())
        else:
            self._priv = serialization.load_pem_private_key(private_key_pem, password=None)

    def sign(self, data: bytes) -> bytes:
        sig = self._priv.sign(data, ec.ECDSA(hashes.SHA256()))
        return sig

    def public_key_pem(self) -> bytes:
        pub = self._priv.public_key()
        return pub.public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
