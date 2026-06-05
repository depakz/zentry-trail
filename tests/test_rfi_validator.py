import asyncio

from modules.pipeline.validation import rfi_validator as rv


def test_rfi_detects(monkeypatch):
    async def fake_fetch(session, url):
        if 'passwd' in url:
            return 0.1, 200, 'root:x:0:0:root:/root:/bin/bash'
        return 0.1, 200, 'ok'

    monkeypatch.setattr(rv, '_fetch', fake_fetch)
    monkeypatch.setattr(rv, 'suggest_payloads', lambda t, n=0: ['file:///etc/passwd'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(rv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(rv.validate_rfi('https://example.com/?u=1', 'u'))
    assert isinstance(res, dict)
    assert 'RFI' in res.get('type')


def test_rfi_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, 'ok'

    monkeypatch.setattr(rv, '_fetch', fake_fetch)
    monkeypatch.setattr(rv, 'suggest_payloads', lambda t, n=0: ['http://evil'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(rv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(rv.validate_rfi('https://example.com/?u=1', 'u'))
    assert res is None
