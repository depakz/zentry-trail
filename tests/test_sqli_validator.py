import asyncio

from types import SimpleNamespace

from modules.pipeline.validation import sqli_validator as sv


class FakeResp:
    def __init__(self, text_value, status=200):
        self._text = text_value
        self.status = status

    async def text(self):
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

    def get(self, url, timeout=0):
        body, status = self.body_map.get(url, ('', 200))
        return RespCM(FakeResp(body, status=status))


def test_error_based_detects_sql_error(monkeypatch):
    # Prepare a session where any test_url returns an SQL error message
    fake = FakeSessionCM(body_map={})
    # patch ClientSession to return our fake session
    async def fake_client_session():
        return fake

    monkeypatch.setattr('aiohttp.ClientSession', lambda: FakeSessionCM(body_map=None))
    # monkeypatch suggest_payloads to include an extra payload
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: ["injected'"])

    # Create a FakeSession that returns SQL error when .get called
    def fake_get(self, url, timeout=0):
        return RespCM(FakeResp('You have an error in your SQL syntax', status=500))

    # Patch the ClientSession class used in module
    class CS:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, url, timeout=0):
            return RespCM(FakeResp('You have an error in your SQL syntax', status=500))

    monkeypatch.setattr('aiohttp.ClientSession', lambda: CS())

    # Avoid engine side-effects
    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_sqli('https://example.com/?id=1', 'id'))
    assert isinstance(res, dict)
    assert res.get('type', '').startswith('Error')


def test_time_based_detects_delay(monkeypatch):
    # Patch suggest_payloads to empty
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: [])

    # Patch _timed to return baseline small then large delays
    calls = {'i': 0}

    async def fake_timed(session, url):
        i = calls['i']
        calls['i'] += 1
        if i == 0:
            return 0.1, 200, 'ok'  # baseline
        if i == 1:
            return 5.5, 200, 'slow'  # first injected
        # second re-test
        return 5.6, 200, 'slow'

    monkeypatch.setattr(sv, '_timed', fake_timed)

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_sqli('https://example.com/?id=1', 'id'))
    assert isinstance(res, dict)
    assert res.get('type', '').startswith('Time')


def test_no_detection_returns_none(monkeypatch):
    # Patch ClientSession to always return safe body
    class CS2:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, url, timeout=0):
            return RespCM(FakeResp('no error here', status=200))

    monkeypatch.setattr('aiohttp.ClientSession', lambda: CS2())
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_sqli('https://example.com/?id=1', 'id'))
    assert res is None
