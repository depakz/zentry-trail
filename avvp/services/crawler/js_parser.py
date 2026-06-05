import re
from typing import List

def extract_js_endpoints(js_text: str) -> List[str]:
    # Very simple regex-based extractor for URLs in JS
    urls = set()
    # match http(s) URLs
    for m in re.finditer(r"https?://[\w./?=&%-]+", js_text):
        urls.add(m.group(0))
    # match simple ajax endpoints '/api/...'
    for m in re.finditer(r"['\"](/[^'\"]+?)['\"]", js_text):
        candidate = m.group(1)
        if any(ext in candidate for ext in ['.php', '.asp', '.aspx', '.json', 'api', '/v']):
            urls.add(candidate)
    return sorted(urls)
