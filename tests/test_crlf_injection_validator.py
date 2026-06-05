import asyncio

from modules.pipeline.validation import crlf_injection_validator as cv


def test_crlf_detects(monkeypatch):
    async def fake_fetch(session, url):
        if 'MYCRLF' in url:
            return 0.1, 200, 'ok', {'X-CRLF': 'injected'}
        return 0.1, 200, 'ok', {}

    monkeypatch.setattr(cv, '_fetch', fake_fetch)
    monkeypatch.setattr(cv, 'suggest_payloads', lambda t, n=0: ['MYCRLF'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(cv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(cv.validate_crlf_injection('https://example.com/?h=1', 'h'))
    assert isinstance(res, dict)
    assert 'CRLF' in res.get('type')


def test_crlf_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, 'ok', {}

    monkeypatch.setattr(cv, '_fetch', fake_fetch)
    monkeypatch.setattr(cv, 'suggest_payloads', lambda t, n=0: ['MYCRLF'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(cv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(cv.validate_crlf_injection('https://example.com/?h=1', 'h'))
    assert res is None
