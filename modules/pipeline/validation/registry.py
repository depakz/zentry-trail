"""Validator registry and discovery utilities.

Provides a simple decorator-based registry for validators, an import-time
auto-discovery helper (imports all _validator.py modules in this package),
and an expanded inference helper to map nuclei tags or parameter names to a
set of likely validator types.
"""
from __future__ import annotations

import importlib
import inspect
import os
from typing import Callable, Iterable

VALIDATOR_REGISTRY: dict[str, Callable] = {}


def register(vuln_type: str):
    """Decorator to register a validator function for `vuln_type`.

    The validator should be an async function with signature like
    ``async def validate_xxx(url: str, param: str, **kwargs)`` and return
    a dict when a finding is confirmed, or ``None`` otherwise.
    """

    def _decorator(func: Callable):
        VALIDATOR_REGISTRY[vuln_type] = func
        return func

    return _decorator


async def validate(vuln_type: str, url: str, param: str, **kwargs):
    """Call the registered validator for `vuln_type` if present.

    Returns the validator result (dict) or ``None`` when not found/negative.
    """
    func = VALIDATOR_REGISTRY.get(vuln_type)
    if func is None:
        return None
    if inspect.iscoroutinefunction(func):
        return await func(url, param, **kwargs)
    # allow sync validators for testability
    return func(url, param, **kwargs)


def auto_discover(package_dir: str | None = None) -> None:
    """Import all validator modules in this package.

    If ``package_dir`` is omitted we discover relative to this file.
    This ensures modules that register themselves via ``@register`` are
    imported and available in ``VALIDATOR_REGISTRY``.
    """
    if package_dir is None:
        package_dir = os.path.dirname(__file__)

    for fname in os.listdir(package_dir):
        if not fname.endswith("_validator.py"):
            continue
        if fname == os.path.basename(__file__):
            continue
        module_name = f"modules.pipeline.validation.{fname[:-3]}"
        try:
            importlib.import_module(module_name)
        except Exception:
            # Discovery should be best-effort; failures are noisy but not fatal
            continue


def infer_vuln_types(param: str, nuclei_tags: Iterable[str] | None = None) -> list[str]:
    """Heuristic mapping from parameter name + nuclei tags to validator types.

    Expanded to catch search, query, username, password, and other
    high-value parameters that the original implementation missed.
    """
    nuclei_tags = set((t or "").lower() for t in (nuclei_tags or []))
    param = (param or "").lower()
    candidates: set[str] = set()

    # ── Nuclei tag → validator mapping ────────────────────────────────────────
    tag_map = {
        "xss":              "xss",
        "sqli":             "sqli",
        "sql":              "sqli",
        "lfi":              "lfi",
        "ssrf":             "ssrf",
        "rfi":              "rfi",
        "ssti":             "ssti",
        "cmdi":             "cmdi",
        "open-redirect":    "open_redirect",
        "xxe":              "xxe",
        "idor":             "idor",
        "biz-logic":        "biz_logic_validator",
        "business-logic":   "biz_logic_validator",
        "crlf":             "crlf_injection",
        "path-traversal":   "path_traversal",
        "injection":        "sqli",
        "reflected":        "xss",
        "access-control":   "broken_access_control",
        "privilege":        "broken_access_control",
        "idor-bac":         "broken_access_control",
    }

    for t in nuclei_tags:
        if t in tag_map:
            candidates.add(tag_map[t])

    # ── Parameter name heuristics — EXPANDED ──────────────────────────────────

    # IDOR signals
    if any(k in param for k in ("id", "user", "uid", "account", "acct",
                                 "member", "customer", "order", "invoice",
                                 "ticket", "record", "doc", "num", "no")):
        candidates.add("idor")

    # File / path inclusion signals
    if any(k in param for k in ("file", "path", "include", "page",
                                  "template", "load", "read", "view",
                                  "dir", "folder")):
        candidates.update({"lfi", "path_traversal"})

    # Open redirect signals
    if any(k in param for k in ("url", "redirect", "next", "return",
                                  "goto", "dest", "destination", "target",
                                  "redir", "continue", "forward", "ref",
                                  "referrer", "content", "link", "href",
                                  "location")):
        candidates.add("open_redirect")

    # Command injection signals
    if any(k in param for k in ("cmd", "exec", "command", "run",
                                  "shell", "system", "ping", "host",
                                  "hostname", "ip", "addr")):
        candidates.add("cmdi")

    # ── SQLi signals — all user-input params are candidates ───────────────────
    # High-confidence SQLi params
    if any(k in param for k in ("query", "search", "q", "keyword",
                                  "name", "username", "user", "login",
                                  "email", "pass", "password", "pwd",
                                  "id", "uid", "acct", "account",
                                  "order", "sort", "filter", "where",
                                  "category", "cat", "type", "status",
                                  "from", "to", "date", "start", "end")):
        candidates.add("sqli")

    # ── XSS signals — all reflection-likely params ────────────────────────────
    # High-confidence XSS params (typically reflected in page)
    if any(k in param for k in ("query", "search", "q", "keyword",
                                  "name", "message", "msg", "comment",
                                  "text", "body", "content", "title",
                                  "desc", "description", "note",
                                  "input", "data", "value", "val",
                                  "term", "s", "find", "look")):
        candidates.add("xss")

    # SSRF signals
    if any(k in param for k in ("url", "host", "server", "endpoint",
                                  "ip", "addr", "dest", "target",
                                  "proxy", "fetch", "load", "src",
                                  "source", "callback", "webhook")):
        candidates.add("ssrf")

    # SSTI signals
    if any(k in param for k in ("template", "tpl", "view", "render",
                                  "layout", "theme", "format")):
        candidates.add("ssti")

    # XXE signals
    if any(k in param for k in ("xml", "data", "input", "payload",
                                  "body", "content")):
        candidates.add("xxe")

    # CRLF injection
    if any(k in param for k in ("redirect", "url", "next", "location",
                                  "header", "ref")):
        candidates.add("crlf_injection")

    # Admin/account path hints → BAC
    # (these come from endpoint_patterns in signal bag, not param names)
    if any(k in param for k in ("admin", "role", "privilege", "access",
                                  "permission", "grant", "isadmin")):
        candidates.add("broken_access_control")

    # ── Universal minimum — every endpoint with ANY param gets basic checks ───
    # Only add sqli + xss if at least some param exists (avoid noise on bare /)
    if param and not candidates:
        candidates.update({"sqli", "xss"})

    # Only return candidates which are registered
    return [c for c in candidates if c in VALIDATOR_REGISTRY]


__all__ = ["VALIDATOR_REGISTRY", "register", "validate", "auto_discover", "infer_vuln_types"]
