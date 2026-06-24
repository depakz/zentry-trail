from types import SimpleNamespace

import zentry.validators.auth as auth_mod
import zentry.validators.access_control as ac_mod


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.raw = SimpleNamespace(headers=self)

    def get_all(self, name):
        return [self.headers.get(name)] if name in self.headers else []


def test_auth_validator_rate_limit_and_cookie(monkeypatch):
    # Simulate multiple successful posts (no 429/403) and insecure Set-Cookie header
    class FakeSession:
        def __init__(self):
            self.posts = 0

        def post(self, url, data=None, headers=None, timeout=None, allow_redirects=None):
            self.posts += 1
            return FakeResponse(status_code=200, text="ok")

        def get(self, url, headers=None, timeout=None, allow_redirects=None):
            return FakeResponse(status_code=200, text="login page", headers={"Set-Cookie": "remember_me=1; Path=/"})

    monkeypatch.setattr(auth_mod, "requests", SimpleNamespace(Session=lambda: FakeSession()))

    validator = auth_mod.AuthValidator()
    state = {"login_url": "https://example.test/login"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
    # evidence contains matched findings
    ev = getattr(res, "evidence", None)
    assert ev is not None
    extra = getattr(ev, "extra", {}) or {}
    assert "login_like" in extra


def test_access_control_idor_detection(monkeypatch):
    # Simulate IDOR - a GET to an idor endpoint returns user-like content
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        body = "<html>User: alice Email: alice@example.test ID: 1</html>"
        return FakeResponse(status_code=200, text=body)

    monkeypatch.setattr(ac_mod, "requests", SimpleNamespace(get=fake_get))

    validator = ac_mod.BrokenAccessControlValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
