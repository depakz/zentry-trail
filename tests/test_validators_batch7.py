from types import SimpleNamespace
from hashlib import sha256

import modules.pipeline.validators.logging as log_mod
import modules.pipeline.validators.integrity as int_mod
import modules.pipeline.validators.stored_xss_validator as sx_mod


def test_logging_validator_missing_headers(monkeypatch):
    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        # Return headers missing standard security headers
        return SimpleNamespace(status_code=200, text="ok", headers={})

    monkeypatch.setattr(log_mod, "requests", SimpleNamespace(get=fake_get))
    v = log_mod.LoggingValidator()
    state = {"url": "https://example.test"}
    res = v.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True


def test_integrity_deserialization_oob(monkeypatch):
    iv = int_mod.IntegrityValidator()

    # body contains suspicious token 'pickle'
    body = {"data": "use pickle to serialize"}

    # oob observer should return True for any probe id
    def oob_observer(probe_id: str) -> bool:
        return True

    res = iv.check_deserialization("https://example.test/api", body, oob_observer=oob_observer)
    assert res is not None
    assert getattr(res, "success", False) is True
    assert getattr(res, "execution_proved", False) is True


def test_integrity_unsigned_packages_detected():
    iv = int_mod.IntegrityValidator()
    manifest = "name: example\nversion: 1.0.0\n"
    res = iv.check_unsigned_packages("https://example.com/repo", manifest_text=manifest)
    assert res is not None
    assert getattr(res, "success", False) is True
    assert getattr(res, "vulnerability", "").startswith("unsigned")


def test_stored_xss_persistence(monkeypatch):
    payload = "<script>alert('zentry')</script>"

    def fake_post(url, data=None, headers=None, timeout=None, allow_redirects=True):
        return SimpleNamespace(status_code=200, text="posted")

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        return SimpleNamespace(status_code=200, text=f"here is comment {payload}")

    monkeypatch.setattr(sx_mod, "requests", SimpleNamespace(post=fake_post, get=fake_get))
    v = sx_mod.StoredXSSValidator()
    state = {"endpoints": ["https://example.test/comment", "https://example.test/profile"]}
    res = v.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
