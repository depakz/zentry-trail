from core.utils import Utils


def test_dedup_urls():
    urls = ['http://a.com', 'http://a.com', 'http://b.com', '']
    out = Utils.dedup_urls(urls)
    assert out == ['http://a.com', 'http://b.com']


def test_normalize_and_base():
    assert Utils.normalize_url('example.com') == 'https://example.com'
    assert Utils.normalize_url('https://ex.com/') == 'https://ex.com'
    assert Utils.get_base_url('https://a.com/path?x=1') == 'https://a.com'


def test_is_static_file():
    assert Utils.is_static_file('https://a.com/image.png')
    assert not Utils.is_static_file('https://a.com/index.html')
