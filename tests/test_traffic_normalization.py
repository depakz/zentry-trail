import pytest
import asyncio
from typing import Dict

from core.traffic_profiles import PROFILES
from core.timing_engine import GaussianTimer, NoiseRequestInjector
from core.normalized_client import NormalizedHTTPClient

def test_profiles_exist():
    assert "chrome124" in PROFILES
    assert "firefox124" in PROFILES
    assert "safari17" in PROFILES

    for p in PROFILES.values():
        assert "User-Agent" in p
        assert "header_order" in p
        assert isinstance(p["header_order"], list)

def test_gaussian_timer():
    timer_web = GaussianTimer(mode="web")
    delays_web = [timer_web.get_delay() for _ in range(100)]
    assert all(0.05 <= d <= 5.0 for d in delays_web)

    timer_api = GaussianTimer(mode="api")
    delays_api = [timer_api.get_delay() for _ in range(100)]
    assert all(0.01 <= d <= 1.0 for d in delays_api)

def test_noise_request_injector():
    injector = NoiseRequestInjector(probability=1.0)
    assert injector.should_inject() is True
    url = injector.get_noise_url("http://example.com")
    assert url.startswith("http://example.com/")
    assert url.endswith((".ico", ".txt", ".png", ".css", ".js"))

def test_normalized_client_headers():
    client = NormalizedHTTPClient(profile_name="safari17")
    headers = client.get_headers()
    order = list(headers.keys())
    expected = [h for h in PROFILES["safari17"]["header_order"] if h in PROFILES["safari17"]]
    assert order == expected
    assert "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" in headers["User-Agent"]

@pytest.mark.asyncio
async def test_normalized_client_get(monkeypatch):
    class FakeResponse:
        def __init__(self, status):
            self.status = status
    class FakeSession:
        async def get(self, url, **kwargs):
            self.last_kwargs = kwargs
            return FakeResponse(200)
    client = NormalizedHTTPClient(profile_name="chrome124", timer_mode="api")
    client.session = FakeSession()
    client.injector = NoiseRequestInjector(probability=0.0)
    resp = await client.get("http://example.com/test", headers={"X-Test": "1"})
    assert resp.status == 200
    assert "X-Test" in list(client.session.last_kwargs["headers"].keys())