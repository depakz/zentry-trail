import asyncio

from modules.pipeline.validation import idor_validator as iv


def test_idor_detects(monkeypatch):
    async def fake_fetch(session, url):
        if 'id=2' in url:
            return 0.1, 200, '{"owner":"admin"}'
        return 0.1, 200, '{"owner":"user"}'

    monkeypatch.setattr(iv, '_fetch', fake_fetch)
    monkeypatch.setattr(iv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(iv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(iv.validate_idor('https://example.com/?id=1', 'id'))
    assert isinstance(res, dict)
    assert 'IDOR' in res.get('type')


def test_idor_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, '{"owner":"user"}'

    monkeypatch.setattr(iv, '_fetch', fake_fetch)
    monkeypatch.setattr(iv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(iv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(iv.validate_idor('https://example.com/?id=1', 'id'))
    assert res is None
