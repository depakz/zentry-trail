import socket
import requests
from types import SimpleNamespace

import zentry.validators.components as comp_mod
import zentry.validators.redis as redis_mod
import zentry.validators.ssrf_validator as ssrf_mod


def test_outdated_components_detects_version_header(monkeypatch):
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        return SimpleNamespace(status_code=200, text="ok", headers={"Server": "nginx/1.2.3"})

    monkeypatch.setattr(comp_mod, "requests", SimpleNamespace(get=fake_get))
    validator = comp_mod.OutdatedComponentsValidator()
    state = {"url": "https://example.test", "findings": []}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
    ev = getattr(res, "evidence", None)
    assert ev is not None
    assert "disclosed_versions" in getattr(ev, "response", {})


def test_redis_no_auth_success(monkeypatch):
    # Fake a socket that returns PONG
    class FakeSocket:
        def __init__(self, *args, **kwargs):
            self.timeout = None

        def settimeout(self, t):
            self.timeout = t

        def connect(self, addr):
            pass

        def send(self, data):
            return len(data)

        def recv(self, size):
            return b"+PONG\r\n"

        def close(self):
            pass

    monkeypatch.setattr(redis_mod, "socket", SimpleNamespace(socket=lambda *a, **k: FakeSocket()))
    validator = redis_mod.RedisNoAuthValidator()
    state = {"target": "127.0.0.1", "ports": [6379]}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True


def test_ssrf_exception_based_confirmation(monkeypatch):
    # baseline request returns OK
    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        if "127.0.0.1" in url or "localhost" in url:
            raise requests.RequestException("Connection refused")
        return SimpleNamespace(status_code=200, text="ok")

    monkeypatch.setattr(ssrf_mod, "requests", SimpleNamespace(get=fake_get, RequestException=requests.RequestException))
    validator = ssrf_mod.SSRFValidator()
    state = {"url": "https://example.test/?url=https://example.com"}
    res = validator.run(state)
    assert res is not None
    assert getattr(res, "success", False) is True
