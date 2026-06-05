import asyncio

from types import SimpleNamespace

from modules.pipeline.validation import open_redirect_validator as orv


class FakeResp:
    def __init__(self, body='', status=200, headers=None):
        self._body = body
        self.status = status
        self.headers = headers or {}

    async def text(self, errors=None):
        return self._body


class RespCM:
    def __init__(self, resp):
        self.resp = resp

    async def __aenter__(self):
        return self.resp

    async def __aexit__(self, *a):
        return False


class SessionCM:
    def __init__(self, responses):
        # responses: map url -> (body, status, headers)
        self.responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, timeout=0):
        # Allow substring matching because query values may be URL-encoded
        for k, v in self.responses.items():
            if k in url:
                body, status, headers = v
                return RespCM(FakeResp(body=body, status=status, headers=headers))
        return RespCM(FakeResp(body='', status=200, headers={}))


def test_open_redirect_detects_location_header(monkeypatch):
    # Prepare session which returns Location header matching payload
    def make_session():
        return SessionCM({
            'r=test': ('baseline', 200, {}),
            'attacker.example.com': ('', 302, {'Location': 'https://attacker.example.com'}),
        })

    monkeypatch.setattr('aiohttp.ClientSession', lambda allow_redirects=False: make_session())
    monkeypatch.setattr(orv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(orv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(orv.validate_open_redirect('https://example.com/?r=1', 'r'))
    assert isinstance(res, dict)
    assert res.get('type') == 'Open Redirect'


def test_open_redirect_no_detection(monkeypatch):
    def make_session():
        return SessionCM({
            'r=test': ('baseline', 200, {}),
            'example.com': ('body', 200, {}),
        })

    monkeypatch.setattr('aiohttp.ClientSession', lambda allow_redirects=False: make_session())
    monkeypatch.setattr(orv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(orv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(orv.validate_open_redirect('https://example.com/?r=1', 'r'))
    assert res is None
