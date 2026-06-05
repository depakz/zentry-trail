import asyncio

from modules.pipeline.validation import path_traversal_validator as pv


def test_path_traversal_detects_signature(monkeypatch):
    async def fake_fetch(session, url):
        if 'test' in url:
            return 0.1, 200, 'baseline'
        return 0.2, 200, 'root:x:0:0:root:/root:/bin/bash'

    monkeypatch.setattr(pv, '_fetch', fake_fetch)
    monkeypatch.setattr(pv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(pv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(pv.validate_path_traversal('https://example.com/?p=1', 'p'))
    assert isinstance(res, dict)
    assert res.get('type') == 'Path Traversal'


def test_path_traversal_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, 'nothing here'

    monkeypatch.setattr(pv, '_fetch', fake_fetch)
    monkeypatch.setattr(pv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(pv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(pv.validate_path_traversal('https://example.com/?p=1', 'p'))
    assert res is None
