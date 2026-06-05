try:
    import httpx
    HAS_HTTPX = True
except Exception:
    HAS_HTTPX = False

from typing import Dict

class SlackIntegration:
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url

    def send_message(self, text: str, extras: Dict = None) -> Dict:
        payload = {'text': text}
        if extras:
            payload.update(extras)
        if HAS_HTTPX and self.webhook_url:
            try:
                r = httpx.post(self.webhook_url, json=payload, timeout=5.0)
                return {'status': r.status_code, 'ok': r.status_code < 300}
            except Exception as e:
                return {'status': 'error', 'error': str(e)}
        # fallback: print to stdout
        print('SLACK:', payload)
        return {'status': 'printed', 'ok': True}
