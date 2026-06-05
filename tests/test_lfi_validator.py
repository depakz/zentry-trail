import asyncio

from modules.pipeline.validation import lfi_validator as lv


def test_lfi_detects_signature(monkeypatch):
    async def fake_fetch(session, url):
        # baseline first call
        if 'test' in url:
            return 0.1, 200, 'baseline'
        # payload call returns /etc/passwd like content
        return 0.2, 200, 'root:x:0:0:root:/root:/bin/bash'

    monkeypatch.setattr(lv, '_fetch', fake_fetch)
    monkeypatch.setattr(lv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(lv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(lv.validate_lfi('https://example.com/?f=1', 'f'))
    assert isinstance(res, dict)
    assert res.get('type') == 'LFI'


def test_lfi_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, 'normal content'

    monkeypatch.setattr(lv, '_fetch', fake_fetch)
    monkeypatch.setattr(lv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(lv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(lv.validate_lfi('https://example.com/?f=1', 'f'))
    assert res is None
