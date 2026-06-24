from types import SimpleNamespace

import zentry.validators.csrf as csrf_mod
import zentry.validators.xxe_validator as xxe_mod
import zentry.validators.open_redirect_validator as or_mod


def test_csrf_missing_protections(monkeypatch):
    # GET returns page without csrf token and Set-Cookie lacks SameSite
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=200, text="<form><input type=\"text\" name=\"user\"></form>", headers={"Set-Cookie": "sessionid=abc; Path=/"})

    def fake_post(url, headers=None, data=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=200, text="ok")

    monkeypatch.setattr(csrf_mod, "requests", SimpleNamespace(get=fake_get, post=fake_post))
    validator = csrf_mod.CSRFValidator()
    state = {"endpoints": ["https://example.test/login"]}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True


def test_xxe_detection(monkeypatch):
    # POST returns body containing 'root:' to simulate local file disclosure
    def fake_post(url, data=None, headers=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=200, text="root:x:0:0:root:/root:/bin/bash")

    monkeypatch.setattr(xxe_mod, "requests", SimpleNamespace(post=fake_post))
    validator = xxe_mod.XXEValidator()
    state = {"url": "https://example.test/upload"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True


def test_open_redirect_detection(monkeypatch):
    # GET probe returns Location header pointing to evil.com
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=302, text="", headers={"Location": "https://evil.com"})

    monkeypatch.setattr(or_mod, "requests", SimpleNamespace(get=fake_get))
    validator = or_mod.OpenRedirectValidator()
    state = {"endpoints": ["https://example.test/redirect?next=https://example.test"], "param_patterns": ["next"]}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
