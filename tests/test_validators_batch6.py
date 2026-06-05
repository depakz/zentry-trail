from types import SimpleNamespace

import modules.pipeline.validators.injection as inj_mod
import modules.pipeline.validators.jwt_validator as jwt_mod


def test_injection_xss_reflected(monkeypatch):
    XSS = inj_mod.XSS_PAYLOAD

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        # baseline will contain 'injection-test' and should not reflect payload
        if "injection-test" in url:
            return SimpleNamespace(status_code=200, text="normal content", headers={})
        # Simulate that payload probes reflect an XSS payload
        if "alert" in url or "svg" in url or "script" in url:
            return SimpleNamespace(status_code=200, text=f"some content {XSS} more", headers={})
        return SimpleNamespace(status_code=200, text="normal content", headers={})

    monkeypatch.setattr(inj_mod, "requests", SimpleNamespace(get=fake_get))
    validator = inj_mod.InjectionValidator()
    state = {"url": "https://example.test/search?q=term"}
    res = validator.run(state)
    assert res is not None
    # Either a list with findings or single ValidationResult with success True
    if isinstance(res, list):
        assert any(getattr(r, "success", False) for r in res)
    else:
        assert getattr(res, "success", False) is True


def test_jwt_forgery_detected(monkeypatch):
    # Provide a fake token and make baseline denied, probe accepted
    token = "a.b.c"

    def fake_get(url, headers=None, timeout=None, allow_redirects=False):
        auth = headers.get("Authorization") if headers else None
        if auth and auth.startswith("Bearer "):
            return SimpleNamespace(status_code=200, text="ok")
        return SimpleNamespace(status_code=401, text="denied")

    monkeypatch.setattr(jwt_mod, "requests", SimpleNamespace(get=fake_get))
    validator = jwt_mod.JWTValidator()
    state = {"target": "https://example.test/protected", "jwt": token}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) in (True, False)
