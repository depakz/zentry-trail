import secrets
import string
from typing import Optional

# URL-safe alphabet (base64url without padding)
ALPHABET = string.ascii_letters + string.digits + '-' + '_'

def generate_token(scan_id: str, finding_id: str) -> str:
    """
    Generate a URL-safe token of 12 random characters.
    The scan_id and finding_id are not used in the token generation for simplicity,
    but they could be incorporated if needed (e.g., for namespacing).
    For now, we just generate a random token.
    """
    return ''.join(secrets.choice(ALPHABET) for _ in range(12))

class OOBCanary:
    """
    Singleton lifecycle manager for the OOB canary server.
    """
    _instance = None
    _server_url = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def start(self, host: str = "0.0.0.0", port: int = 8877) -> str:
        """
        Start the canary server and return the base URL.
        """
        # Import here to avoid circular imports if needed
        from oob_canary.server import start_canary_server
        self._server_url = await start_canary_server(host, port)
        return self._server_url

    async def stop(self):
        """
        Stop the canary server.
        """
        from oob_canary.server import stop_canary_server
        await stop_canary_server()
        self._server_url = None

    @property
    def base_url(self) -> Optional[str]:
        return self._server_url
       
# Convenience function to get the singleton instance
def get_canary() -> OOBCanary:
    return OOBCanary()