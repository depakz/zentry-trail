import asyncio

from types import SimpleNamespace

from modules.pipeline.validation import xss_validator as xv


class FakeResponse:
    def __init__(self, status=200):
        self.status = status


class FakePage:
    def __init__(self, evaluate_result=False, content_text='body', status=200):
        self._evaluate_result = evaluate_result
        self._content_text = content_text
        self._status = status
        self._handlers = {}

    async def goto(self, url, timeout=0, wait_until=None):
        return FakeResponse(status=self._status)

    async def content(self):
        return self._content_text

    async def evaluate(self, script):
        return self._evaluate_result

    def on(self, event, handler):
        # store handler; tests won't invoke dialog
        self._handlers[event] = handler


class FakeContext:
    def __init__(self, page):
        self._page = page

    async def new_page(self):
        return self._page

    async def close(self):
        return None

    async def add_cookies(self, cookies):
        return None


class FakeBrowser:
    def __init__(self, page):
        self._page = page

    async def new_context(self, *args, **kwargs):
        return FakeContext(self._page)


def make_fake_browser(evaluate_result=False, content_text='body', status=200):
    page = FakePage(evaluate_result=evaluate_result, content_text=content_text, status=status)
    return FakeBrowser(page)


def test_validate_xss_returns_finding_when_payload_triggers(monkeypatch):
    # Provide a browser where evaluate returns True (payload triggered)
    async def fake_get_browser():
        return make_fake_browser(evaluate_result=True)

    monkeypatch.setattr(xv, '_get_browser', fake_get_browser)
    monkeypatch.setattr(xv, 'suggest_payloads', lambda t, n=0: ['PAYLOAD1'])

    # Replace AdaptiveExploitEngine to avoid side-effects
    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(xv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(xv.validate_xss('https://example.com/?q=1', 'q', timeout=1))
    assert isinstance(res, dict)
    assert res.get('validated') is True


def test_validate_xss_returns_none_when_no_trigger(monkeypatch):
    async def fake_get_browser():
        return make_fake_browser(evaluate_result=False, content_text='no trigger')

    monkeypatch.setattr(xv, '_get_browser', fake_get_browser)
    monkeypatch.setattr(xv, 'suggest_payloads', lambda t, n=0: ['p1', 'p2'])

    class DummyEngine:
        def record_result(self, *a, **k):
            return None

    monkeypatch.setattr(xv, 'AdaptiveExploitEngine', DummyEngine)

    res = asyncio.run(xv.validate_xss('https://example.com/?q=1', 'q', timeout=1))
    assert res is None
