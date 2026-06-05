import os
import subprocess
from types import SimpleNamespace

import core.nuclei_runner as nr
from core.nuclei_runner import NucleiRunner
from core.utils import Utils


def test_run_batch_empty():
    res = NucleiRunner.run_batch([], batch_num=1)
    assert res['scanned'] == 0 and res['findings'] == []


def test_run_batch_parses_json_and_ignores_bad_lines(monkeypatch, tmp_path):
    # Mock resolve_binary
    monkeypatch.setattr('modules.pipeline.utils.binaries.resolve_binary', lambda x: '/bin/nuclei')

    # Mock Utils.run_command to return JSON lines and some noise
    def fake_run(cmd, timeout=0, shell=True):
        out = '{"id": 1}\nnot-a-json\n{"id": 2}\n'
        return out, 0

    monkeypatch.setattr(Utils, 'run_command', staticmethod(fake_run))

    urls = [f'https://example.com/{i}' for i in range(3)]
    res = NucleiRunner.run_batch(urls, batch_num=5)
    assert res['scanned'] == 3
    assert isinstance(res['findings'], list)
    assert len(res['findings']) == 2


def test_run_batch_timeout_retries_and_returns_zero(monkeypatch):
    # Force Utils.run_command to raise TimeoutExpired
    def raise_timeout(cmd, timeout=0, shell=True):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(Utils, 'run_command', staticmethod(raise_timeout))

    urls = [f'https://example.com/{i}' for i in range(12)]
    res = NucleiRunner.run_batch(urls, batch_num=2)
    # After repeated timeouts the method should return a zero-scanned dict
    assert res['scanned'] == 0
    assert res['findings'] == []


def test_scan_endpoints_batches(monkeypatch):
    called = []

    def fake_run_batch(batch, batch_num, templates=None, tags=None):
        called.append((len(batch), batch_num))
        # return one finding per url for easy assertion
        return {'findings': [{'u': u} for u in batch], 'scanned': len(batch)}

    monkeypatch.setattr(NucleiRunner, 'run_batch', staticmethod(fake_run_batch))

    endpoints = {
        'parameterized': [f'https://a/{i}' for i in range(30)],
        'api': [f'https://api/{i}' for i in range(3)],
    }

    res = NucleiRunner.scan_endpoints(endpoints)
    # Expect scanned equals total urls
    assert res['scanned'] == 33
    # Findings should equal number of urls
    assert len(res['findings']) == 33
    # Ensure batching occurred (first batch size = 25)
    assert any(c[0] == 25 for c in called)
