import os
import json
import sys
import tempfile
import shutil
import time
import subprocess

from core.utils import Utils


def test_ensure_and_save_load_json(tmp_path):
    d = {'a': 1}
    file = tmp_path / 'sub' / 'data.json'
    Utils.save_json(d, str(file))
    loaded = Utils.load_json(str(file))
    assert loaded == d


def test_read_write_lines(tmp_path):
    file = tmp_path / 'lines' / 'items.txt'
    Utils.write_lines({'b', 'a'}, str(file))
    s = Utils.read_lines(str(file))
    assert 'a' in s and 'b' in s


def test_run_command_success_and_timeout():
    out, code = Utils.run_command('echo hello', timeout=5)
    assert 'hello' in out
    # Timeout: run a python sleep with tiny timeout
    cmd = f"{sys.executable} -c 'import time; time.sleep(2)'"
    out2, code2 = Utils.run_command(cmd, timeout=1)
    assert code2 != 0


def test_tool_exists():
    # `which` behavior depends on environment; just assert boolean
    assert isinstance(Utils.tool_exists('python'), bool)
    assert Utils.tool_exists('some_nonexistent_tool_12345') is False


def test_timestamp_and_dedup_urls():
    ts = Utils.get_timestamp()
    assert isinstance(ts, str) and len(ts) > 0
    urls = ['http://a', 'http://a', 'http://b']
    out = Utils.dedup_urls(urls)
    assert out == ['http://a', 'http://b']


def test_url_helpers():
    assert Utils.is_static_file('image.png')
    assert not Utils.is_static_file('/api/data')
    assert Utils.normalize_url('example.com') == 'https://example.com'
    assert Utils.normalize_url('https://example.com/') == 'https://example.com'
    assert Utils.extract_domain('https://a.example.com/path') == 'a.example.com'
    assert Utils.get_base_url('https://a.example.com/path?q=1') == 'https://a.example.com'
