"""Signatures for OWASP Juice Shop error logs to confirm vulnerabilities."""

from __future__ import annotations

import re
from typing import Iterable

JUICE_SHOP_SIGNATURES = [
    re.compile(r"SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"SequelizeDatabaseError", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR: near &quot;", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR: near &quot;.*&quot;: syntax error", re.IGNORECASE),
    re.compile(r"SequelizeDatabaseError: SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"Error: SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"SQLITE_CANTOPEN", re.IGNORECASE),
    re.compile(r"SQLITE_CONSTRAINT", re.IGNORECASE),
    re.compile(r"at\s+verify\s+\(/juice-shop/build/routes/fileServer\.js", re.IGNORECASE),
    re.compile(r"/juice-shop/build/routes/fileServer\.js", re.IGNORECASE),
    re.compile(r"/juice-shop/build/routes/verify\.js", re.IGNORECASE),
    re.compile(r"juice-shop/build/routes/fileServer\.js", re.IGNORECASE),
    re.compile(r"juice-shop stack trace", re.IGNORECASE),
]


def _to_text_fragments(value: object) -> Iterable[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        fragments = []
        for item in value.values():
            fragments.extend(_to_text_fragments(item))
        return fragments
    if isinstance(value, (list, tuple, set)):
        fragments = []
        for item in value:
            fragments.extend(_to_text_fragments(item))
        return fragments
    return [str(value)]


def check_juice_shop_error(response_text: object) -> bool:
    """Checks whether the supplied content contains any known Juice Shop signatures."""
    for fragment in _to_text_fragments(response_text):
        for pattern in JUICE_SHOP_SIGNATURES:
            if pattern.search(fragment):
                return True
    return False
