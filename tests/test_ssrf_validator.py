import asyncio

from modules.pipeline.validation import ssrf_validator as sv


def test_ssrf_detects_signature(monkeypatch):
    async def fake_fetch(session, url):
        # baseline
        if 'test' in url:
            return 0.1, 200, 'baseline'
        return 0.2, 200, 'instance-id: i-12345'

    monkeypatch.setattr(sv, '_fetch', fake_fetch)
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_ssrf('https://example.com/?u=1', 'u'))
    assert isinstance(res, dict)
    assert res.get('type') == 'SSRF'


def test_ssrf_no_detection(monkeypatch):
    async def fake_fetch(session, url):
        return 0.1, 200, 'no ssrf here'

    monkeypatch.setattr(sv, '_fetch', fake_fetch)
    monkeypatch.setattr(sv, 'suggest_payloads', lambda t, n=0: [])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(sv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(sv.validate_ssrf('https://example.com/?u=1', 'u'))
    assert res is None
