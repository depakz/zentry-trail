import asyncio
from avvp.services.crawler.js_parser import extract_js_endpoints
from avvp.services.crawler.param_finder import param_names


def test_js_parser():
    js = """
    var api = '/api/v1/users';
    fetch('/v1/login');
    var x = "https://cdn.example.com/lib.js";
    """
    eps = extract_js_endpoints(js)
    assert '/api/v1/users' in eps or '/v1/login' in eps


def test_param_finder():
    url = 'https://example.com/search?q=apple&lang=en'
    params = param_names(url)
    assert 'q' in params and 'lang' in params
