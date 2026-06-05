import asyncio

from modules.pipeline.validation import cmdi_validator as cv


def test_cmdi_detects(monkeypatch):
    async def fake_timed(session, url):
        if 'sleep' in url:
            return 5.5, 200, 'delayed'
        return 0.1, 200, 'ok'

    monkeypatch.setattr(cv, '_timed', fake_timed)
    monkeypatch.setattr(cv, 'suggest_payloads', lambda t, n=0: ['; sleep 5'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(cv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(cv.validate_cmdi('https://example.com/?q=1', 'q'))
    assert isinstance(res, dict)
    assert 'Command Injection' in res.get('type')


def test_cmdi_no_detection(monkeypatch):
    async def fake_timed(session, url):
        return 0.1, 200, 'nothing'

    monkeypatch.setattr(cv, '_timed', fake_timed)
    monkeypatch.setattr(cv, 'suggest_payloads', lambda t, n=0: [';ping'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(cv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(cv.validate_cmdi('https://example.com/?q=1', 'q'))
    assert res is None
