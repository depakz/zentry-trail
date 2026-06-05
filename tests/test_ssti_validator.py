import asyncio

from modules.pipeline.validation import ssti_validator as sv


def test_ssti_detects(monkeypatch):
    async def fake_fetch(session, url):
        if 'PAYLOAD49' in url:
            return 0.1, 200, '49'
        return 0.1, 200, 'ok'

    monkeypatch.setattr(sv, '_fetch', fake_fetch)
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: ['PAYLOAD49'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_ssti('https://example.com/?name=1', 'name'))
    assert isinstance(res, dict)
    assert 'SSTI' in res.get('type')


def test_ssti_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, 'ok'

    monkeypatch.setattr(sv, '_fetch', fake_fetch)
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: ['{{7*7}}'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_ssti('https://example.com/?name=1', 'name'))
    assert res is None
