import zentry.validators.crypto as crypto_mod
import zentry.validators.access_control as ac_mod
from types import SimpleNamespace


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.raw = SimpleNamespace(headers=self)


def test_crypto_weak_tls_branch(monkeypatch):
    # Simulate a TLS probe that accepts TLSv1 (weak)
    def fake_probe(host, port, timeout):
        return {
            "accepted_versions": ["TLSv1", "TLSv1.2"],
            "errors": {},
            "cipher_info": {"TLSv1": "RC4-SHA"},
        }

    monkeypatch.setattr(crypto_mod, "_probe_tls_versions", fake_probe)

    validator = crypto_mod.CryptoValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
    # Expect vulnerability a02-crypto-weak-tls or weak-cipher depending on ordering
    vuln = getattr(res, "vulnerability", "")
    assert vuln.startswith("a02-crypto-")


def test_crypto_missing_security_headers(monkeypatch):
    # Simulate requests.get returning headers missing security headers
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return FakeResponse(status_code=200, text="ok", headers={})

    monkeypatch.setattr(crypto_mod, "requests", SimpleNamespace(get=fake_get))

    validator = crypto_mod.CryptoValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    # Should detect missing security headers if 3+ are missing
    assert getattr(res, "success", False) is True
    assert getattr(res, "vulnerability", "").startswith("a02-crypto-")


def test_access_control_privilege_escalation_branch(monkeypatch):
    # Force _test_privilege_escalation to return a positive result
    monkeypatch.setattr(ac_mod, "_test_privilege_escalation", lambda base, h, ah, t: {"endpoint": f"{base}/admin", "unauth_status": 200, "admin_status": 200})

    validator = ac_mod.BrokenAccessControlValidator()
    state = {"url": "https://example.test"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
    assert getattr(res, "vulnerability", "") == "a01-broken-access-control-privilege-escalation"
