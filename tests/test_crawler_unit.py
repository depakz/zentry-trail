from core.crawler import Crawler
from core.utils import Utils


def test_crawl_katana_parses_urls(monkeypatch):
    def fake_run(cmd, timeout=0, shell=True):
        return 'https://a.example.com/page1\nnot-a-url\nhttp://b.test/img.png\n', 0

    monkeypatch.setattr(Utils, 'run_command', staticmethod(fake_run))
    urls = Crawler.crawl_katana('https://example.com')
    assert any('a.example.com' in u for u in urls)


def test_crawl_gau_and_wayback(monkeypatch):
    def fake_run_gau(cmd, timeout=0, shell=True):
        return 'https://site/page\nhttps://site/static.js\n', 0

    monkeypatch.setattr(Utils, 'run_command', staticmethod(fake_run_gau))
    gau = Crawler.crawl_gau('example.com')
    assert any('site/page' in u for u in gau)

    monkeypatch.setattr(Utils, 'run_command', staticmethod(lambda *a, **k: ('https://wb/u', 0)))
    wb = Crawler.crawl_waybackurls('example.com')
    assert 'https://wb/u' in wb


def test_crawl_handles_exceptions(monkeypatch):
    def raise_exc(cmd, timeout=0, shell=True):
        raise RuntimeError('boom')

    monkeypatch.setattr(Utils, 'run_command', staticmethod(raise_exc))
    assert Crawler.crawl_katana('https://x') == set()
    assert Crawler.crawl_gau('x') == set()
    assert Crawler.crawl_waybackurls('x') == set()


def test_discover_endpoints_aggregates_and_filters(monkeypatch):
    # Mock Crawler.crawl_katana to return urls including static files
    monkeypatch.setattr(Crawler, 'crawl_katana', staticmethod(lambda u, timeout=0, depth=0: {'https://a/page', 'https://a/image.png'}))
    # Mock Crawler.crawl_gau to return additional urls
    monkeypatch.setattr(Crawler, 'crawl_gau', staticmethod(lambda d, timeout=0: {'https://a/api', 'https://a/style.css'}))

    res = Crawler.discover_endpoints(['example.com'], tier='tier1')
    # katana and gau sets present
    assert 'katana' in res and 'gau' in res and 'all' in res
    # filtered 'all' should not include static files
    assert all(not u.endswith('.png') and not u.endswith('.css') for u in res['all'])

    # tier2 should skip gau
    called = {'gau': False}
    def fake_gau(domain, timeout=0):
        called['gau'] = True
        return set()

    monkeypatch.setattr(Crawler, 'crawl_gau', staticmethod(fake_gau))
    _ = Crawler.discover_endpoints(['example.com'], tier='tier2')
    assert called['gau'] is False
