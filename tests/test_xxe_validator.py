import asyncio

from modules.pipeline.validation import xxe_validator as xv


def test_xxe_detects(monkeypatch):
    async def fake_fetch(session, url):
        if 'PAYLOAD_ROOT' in url:
            return 0.1, 200, 'root:x:0:0:root:/root:/bin/bash'
        return 0.1, 200, 'ok'

    monkeypatch.setattr(xv, '_fetch', fake_fetch)
    monkeypatch.setattr(xv, 'suggest_payloads', lambda t, n=0: ['PAYLOAD_ROOT'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(xv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(xv.validate_xxe('https://example.com/?d=1', 'd'))
    assert isinstance(res, dict)
    assert 'XXE' in res.get('type')


def test_xxe_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, 'ok'

    monkeypatch.setattr(xv, '_fetch', fake_fetch)
    monkeypatch.setattr(xv, 'suggest_payloads', lambda t, n=0: ['xxe'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(xv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(xv.validate_xxe('https://example.com/?d=1', 'd'))
    assert res is None
