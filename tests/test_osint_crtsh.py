import pytest
import types
import asyncio

from avvp.services.osint.crtsh_runner import CRTSHRunner


class FakeResponse:
    def __init__(self, status_code=200, data=None, raise_on_json=False):
        self.status_code = status_code
        self._data = data
        self._raise = raise_on_json

    def json(self):
        if self._raise:
            raise ValueError("bad json")
        return self._data


class FakeClient:
    def __init__(self, response: FakeResponse):
        self._resp = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url):
        return self._resp


def test_crtsh_success(monkeypatch):
    data = [
        {"name_value": "a.example.com\nb.example.com"},
        {"name_value": "c.example.com"},
    ]
    fake = FakeResponse(status_code=200, data=data)
    monkeypatch.setattr('httpx.AsyncClient', lambda timeout=30: FakeClient(fake))

    runner = CRTSHRunner()
    res = asyncio.run(runner.run('example.com'))
    assert res == ['a.example.com', 'b.example.com', 'c.example.com']


def test_crtsh_non200(monkeypatch):
    fake = FakeResponse(status_code=500, data=None)
    monkeypatch.setattr('httpx.AsyncClient', lambda timeout=30: FakeClient(fake))

    runner = CRTSHRunner()
    res = asyncio.run(runner.run('example.com'))
    assert res == []


def test_crtsh_bad_json(monkeypatch):
    fake = FakeResponse(status_code=200, data=None, raise_on_json=True)
    monkeypatch.setattr('httpx.AsyncClient', lambda timeout=30: FakeClient(fake))

    runner = CRTSHRunner()
    res = asyncio.run(runner.run('example.com'))
    assert res == []
