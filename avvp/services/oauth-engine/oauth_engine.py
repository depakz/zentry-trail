from typing import Dict, Any
import httpx

class OAuthEngine:
    def __init__(self):
        pass

    async def check_open_redirect(self, callback_url: str) -> bool:
        # heuristic: if callback_url contains a redirect param that is not same-origin
        parsed = callback_url
        # In real implementation parse and test via HTTP
        return 'redirect_uri=' in callback_url or 'next=' in callback_url

    async def validate_pkce(self, params: Dict[str, Any]) -> bool:
        # check presence of code_challenge and proper method
        return 'code_challenge' in params and params.get('code_challenge_method','') in ('S256','plain')
