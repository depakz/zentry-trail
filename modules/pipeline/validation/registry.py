"""Validator registry and discovery utilities.

Provides a simple decorator-based registry for validators, an import-time
auto-discovery helper (imports all _validator.py modules in this package),
and a small inference helper to map nuclei tags or parameter names to a
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

    This is intentionally conservative — it returns only likely validator
    types that exist in the registry.
    """
    nuclei_tags = set((t or "").lower() for t in (nuclei_tags or []))
    param = (param or "").lower()
    candidates: set[str] = set()

    tag_map = {
        "xss": "xss",
        "sqli": "sqli",
        "sql": "sqli",
        "lfi": "lfi",
        "ssrf": "ssrf",
        "rfi": "rfi",
        "ssti": "ssti",
        "cmdi": "cmdi",
        "open-redirect": "open_redirect",
        "xxe": "xxe",
        "idor": "idor",
        "crlf": "crlf_injection",
        "path-traversal": "path_traversal",
    }

    for t in nuclei_tags:
        if t in tag_map:
            candidates.add(tag_map[t])

    # param heuristics
    if any(k in param for k in ("id", "user", "uid", "account")):
        candidates.add("idor")
    if any(k in param for k in ("file", "path", "include", "page", "template")):
        candidates.update({"lfi", "path_traversal"})
    if any(k in param for k in ("url", "redirect", "next")):
        candidates.add("open_redirect")
    if any(k in param for k in ("cmd", "exec", "command")):
        candidates.add("cmdi")

    # Only return candidates which are registered
    return [c for c in candidates if c in VALIDATOR_REGISTRY]


__all__ = ["VALIDATOR_REGISTRY", "register", "validate", "auto_discover", "infer_vuln_types"]
