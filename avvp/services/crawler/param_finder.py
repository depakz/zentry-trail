from urllib.parse import urlparse, parse_qs
from typing import Dict, List


def extract_params_from_url(url: str) -> Dict[str, List[str]]:
    p = urlparse(url)
    return parse_qs(p.query)


def param_names(url: str) -> List[str]:
    params = extract_params_from_url(url)
    return sorted(params.keys())
