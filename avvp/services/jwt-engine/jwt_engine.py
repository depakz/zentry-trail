import jwt
from typing import Tuple, Optional

# Note: PyJWT is used for token parsing; this module contains non-destructive checks only

class JWTEngine:
    def __init__(self):
        pass

    def check_alg_none(self, token: str) -> bool:
        try:
            header = jwt.get_unverified_header(token)
            return header.get('alg', '') == 'none'
        except Exception:
            return False

    def try_rs256_as_hs256(self, token: str, public_key: str) -> bool:
        # attempt to verify RS256 token by treating public key as HMAC secret (alg confusion)
        try:
            jwt.decode(token, public_key, algorithms=['HS256'])
            return True
        except Exception:
            return False
