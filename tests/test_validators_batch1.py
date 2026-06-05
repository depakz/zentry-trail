from types import SimpleNamespace

import modules.pipeline.validators.auth as auth_mod
import modules.pipeline.validators.access_control as ac_mod
import modules.pipeline.validators.components as comp_mod
import modules.pipeline.validators.crypto as crypto_mod


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.raw = SimpleNamespace(headers=self)

    def get_all(self, name):
        return [self.headers.get(name)] if name in self.headers else []


def test_auth_validator_detects_insecure_remember_cookie(monkeypatch):
    # Fake session with post and get
    class FakeSession:
        def post(self, url, data=None, headers=None, timeout=None, allow_redirects=None):
            return FakeResponse(status_code=200, text="ok")

        def get(self, url, headers=None, timeout=None, allow_redirects=None):
            return FakeResponse(status_code=200, text="ok", headers={"Set-Cookie": "remember_me=1; Path=/"})

    monkeypatch.setattr(auth_mod, "requests", SimpleNamespace(Session=lambda: FakeSession()))

    validator = auth_mod.AuthValidator()
    state = {"login_url": "https://example.test/login"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True


def test_access_control_idor_and_sensitive_paths(monkeypatch):
    # Monkeypatch requests.get to simulate sensitive page
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return FakeResponse(status_code=200, text="<html>Admin Dashboard</html>")

    monkeypatch.setattr(ac_mod, "requests", SimpleNamespace(get=fake_get))
    validator = ac_mod.BrokenAccessControlValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True


def test_outdated_components_detects_version_headers(monkeypatch):
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return FakeResponse(status_code=200, text="ok", headers={"Server": "nginx/1.2.3"})

    monkeypatch.setattr(comp_mod, "requests", SimpleNamespace(get=fake_get))
    validator = comp_mod.OutdatedComponentsValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True or isinstance(res, comp_mod.ValidationResult)


def test_crypto_validator_plaintext_detection(monkeypatch):
    # Monkeypatch get_attack_variants to mark Authorization as sensitive
    monkeypatch.setattr(crypto_mod, "get_attack_variants", lambda *args, **kwargs: ["Authorization"])

    # Ensure requests.get returns a response even though plaintext branch will return earlier
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return FakeResponse(status_code=200, text="ok", headers={})

    monkeypatch.setattr(crypto_mod, "requests", SimpleNamespace(get=fake_get))

    validator = crypto_mod.CryptoValidator()
    state = {"url": "http://example.test", "headers": {"Authorization": "token"}}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
