from types import SimpleNamespace

import modules.pipeline.validators.misconfiguration as mis_mod


def test_options_trace_detected(monkeypatch):
    def fake_options(url, headers=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=200, headers={"Allow": "GET, POST, TRACE"})

    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=200, text="ok", headers={})

    monkeypatch.setattr(mis_mod, "requests", SimpleNamespace(options=fake_options, get=fake_get))
    validator = mis_mod.SecurityMisconfigurationValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
    assert getattr(res, "vulnerability", "").endswith("trace")


def test_directory_listing_detection(monkeypatch):
    def fake_options(url, headers=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=200, headers={})

    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        # Simulate directory listing content for candidate_url
        return SimpleNamespace(status_code=200, text="Index of /\nParent Directory", headers={"title": "Index of"})

    monkeypatch.setattr(mis_mod, "requests", SimpleNamespace(options=fake_options, get=fake_get))
    validator = mis_mod.SecurityMisconfigurationValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
    # Accept any misconfiguration confirmation variant (debug or directory listing)
    assert getattr(res, "vulnerability", "").startswith("a05-security-misconfiguration")


def test_common_app_detection(monkeypatch):
    # Simulate detection of wp-includes (WordPress)
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        if url.endswith("/wp-includes/"):
            return SimpleNamespace(status_code=200, text="WordPress files here")
        return SimpleNamespace(status_code=404, text="not found")

    monkeypatch.setattr(mis_mod, "requests", SimpleNamespace(options=lambda *a, **k: SimpleNamespace(status_code=200, headers={}), get=fake_get))
    validator = mis_mod.SecurityMisconfigurationValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
    assert "WordPress" in str(res)
