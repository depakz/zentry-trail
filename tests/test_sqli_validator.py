import asyncio

from types import SimpleNamespace

from modules.pipeline.validation import sqli_validator as sv


class FakeResp:
    def __init__(self, text_value, status=200):
        self._text = text_value
        self.status = status

    async def text(self, *args, **kwargs):
        return self._text


class RespCM:
    def __init__(self, resp):
        self.resp = resp

    async def __aenter__(self):
        return self.resp

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSessionCM:
    def __init__(self, body_map=None):
        # body_map: url -> (body, status)
        self.body_map = body_map or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, url, timeout=None, **kwargs):
        body, status = self.body_map.get(url, ('', 200))
        return RespCM(FakeResp(body, status=status))

    def post(self, url, data=None, timeout=None, **kwargs):
        return RespCM(FakeResp('', status=200))


def test_error_based_detects_sql_error(monkeypatch):
    # monkeypatch suggest_payloads to include an extra payload
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: ["injected'"])

    # Patch the ClientSession class used in module
    class CS:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, url, timeout=None, **kwargs):
            return RespCM(FakeResp('You have an error in your SQL syntax', status=500))

        def post(self, url, data=None, timeout=None, **kwargs):
            return RespCM(FakeResp('You have an error in your SQL syntax', status=500))

    monkeypatch.setattr('aiohttp.ClientSession', lambda: CS())

    # Avoid engine side-effects
    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_sqli('https://example.com/?id=1', 'id'))
    assert isinstance(res, dict)
    assert res.get('validated') is True
    assert "error" in res.get('type', '').lower()


def test_time_based_detects_delay(monkeypatch):
    # Patch suggest_payloads to empty
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: [])

    # Patch _get and _post based on payload presence
    async def fake_get(session, url, cookies=None):
        if any(p in url for p in sv.ALL_TIME_PAYLOADS):
            return 5.5, 200, 'slow'
        return 0.1, 200, 'ok'

    async def fake_post(session, url, data, cookies=None):
        if any(p in str(data) for p in sv.ALL_TIME_PAYLOADS):
            return 5.5, 200, 'slow'
        return 0.1, 200, 'ok'

    monkeypatch.setattr(sv, '_get', fake_get)
    monkeypatch.setattr(sv, '_post', fake_post)

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_sqli('https://example.com/?id=1', 'id'))
    assert isinstance(res, dict)
    assert "time" in res.get('type', '').lower()


def test_no_detection_returns_none(monkeypatch):
    # Patch ClientSession to always return safe body
    class CS2:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, url, timeout=None, **kwargs):
            return RespCM(FakeResp('no error here', status=200))

        def post(self, url, data=None, timeout=None, **kwargs):
            return RespCM(FakeResp('no error here', status=200))

    monkeypatch.setattr('aiohttp.ClientSession', lambda: CS2())
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: [])

    # Patch _get and _post to return baseline responses always
    async def fake_get(session, url, cookies=None):
        return 0.1, 200, 'ok'

    async def fake_post(session, url, data, cookies=None):
        return 0.1, 200, 'ok'

    monkeypatch.setattr(sv, '_get', fake_get)
    monkeypatch.setattr(sv, '_post', fake_post)

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_sqli('https://example.com/?id=1', 'id'))
    assert res is None
