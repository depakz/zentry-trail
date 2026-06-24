from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
from typing import Any, Callable, Dict, Iterable, List, Tuple, Union

VALIDATOR_REGISTRY: dict[str, Callable] = {}


def register(vuln_type: str):
    """Decorator to register a validator function for `vuln_type`."""
    def _decorator(func: Callable):
        VALIDATOR_REGISTRY[vuln_type] = func
        return func
    return _decorator


async def validate(vuln_type: str, url: str, param: str, **kwargs):
    """Call the registered validator for `vuln_type` if present."""
    func = VALIDATOR_REGISTRY.get(vuln_type)
    if func is None:
        return None
    if inspect.iscoroutinefunction(func):
        return await func(url, param, **kwargs)
    return func(url, param, **kwargs)


def auto_discover(package_dir: str | None = None) -> None:
    """Import all validator modules in this package."""
    if package_dir is None:
        package_dir = os.path.dirname(__file__)

    for fname in os.listdir(package_dir):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        module_name = f"zentry.validators.{fname[:-3]}"
        try:
            importlib.import_module(module_name)
        except Exception:
            continue


def infer_vuln_types(param: str, nuclei_tags: Iterable[str] | None = None) -> list[str]:
    """Heuristic mapping from parameter name + nuclei tags to validator types."""
    nuclei_tags = set((t or "").lower() for t in (nuclei_tags or []))
    param = (param or "").lower()
    candidates: set[str] = set()

    tag_map = {
        "xss": "xss", "sqli": "sqli", "sql": "sqli", "lfi": "lfi",
        "ssrf": "ssrf", "rfi": "rfi", "ssti": "ssti", "cmdi": "cmdi",
        "open-redirect": "open_redirect", "xxe": "xxe", "idor": "idor",
        "biz-logic": "biz_logic", "business-logic": "biz_logic",
        "crlf": "crlf_injection", "path-traversal": "path_traversal",
        "injection": "sqli", "reflected": "xss",
        "access-control": "broken_access_control",
        "privilege": "broken_access_control",
        "idor-bac": "broken_access_control",
    }
    for t in nuclei_tags:
        if t in tag_map:
            candidates.add(tag_map[t])

    if any(k in param for k in ("id", "user", "uid", "account", "acct", "member", "customer", "order", "invoice", "ticket", "record", "doc", "num", "no")):
        candidates.add("idor")
    if any(k in param for k in ("file", "path", "include", "page", "template", "load", "read", "view", "dir", "folder")):
        candidates.update({"lfi", "path_traversal"})
    if any(k in param for k in ("url", "redirect", "next", "return", "goto", "dest", "destination", "target", "redir", "continue", "forward", "ref", "referrer", "content", "link", "href", "location")):
        candidates.add("open_redirect")
    if any(k in param for k in ("cmd", "exec", "command", "run", "shell", "system", "ping", "host", "hostname", "ip", "addr")):
        candidates.add("cmdi")
    if any(k in param for k in ("query", "search", "q", "keyword", "name", "username", "user", "login", "email", "pass", "password", "pwd", "id", "uid", "acct", "account", "order", "sort", "filter", "where", "category", "cat", "type", "status", "from", "to", "date", "start", "end")):
        candidates.add("sqli")
    if any(k in param for k in ("query", "search", "q", "keyword", "name", "message", "msg", "comment", "text", "body", "content", "title", "desc", "description", "note", "input", "data", "value", "val", "term", "s", "find", "look")):
        candidates.add("xss")
    if any(k in param for k in ("url", "host", "server", "endpoint", "ip", "addr", "dest", "target", "proxy", "fetch", "load", "src", "source", "callback", "webhook")):
        candidates.add("ssrf")
    if any(k in param for k in ("template", "tpl", "view", "render", "layout", "theme", "format")):
        candidates.add("ssti")
    if any(k in param for k in ("xml", "data", "input", "payload", "body", "content")):
        candidates.add("xxe")
    if any(k in param for k in ("redirect", "url", "next", "location", "header", "ref")):
        candidates.add("crlf_injection")
    if any(k in param for k in ("admin", "role", "privilege", "access", "permission", "grant", "isadmin")):
        candidates.add("broken_access_control")

    if param and not candidates:
        candidates.update({"sqli", "xss"})

    return [c for c in candidates if c in VALIDATOR_REGISTRY]

def _safe_iter(values: Any) -> Iterable[Any]:
    if isinstance(values, list):
        return values
    return []


def _normalize_str_set(values: Iterable[Any]) -> set[str]:
    out = set()
    for value in values:
        if isinstance(value, str) and value.strip():
            out.add(value.strip().lower())
    return out


def _match_signal_values(needle_values: List[Any], hay_values: List[Any], mode: str = "contains") -> bool:
    if not needle_values:
        return True
    if not hay_values:
        return False

    if mode == "int":
        hay = set()
        for item in hay_values:
            try:
                hay.add(int(item))
            except Exception:
                continue
        for needle in needle_values:
            try:
                if int(needle) in hay:
                    return True
            except Exception:
                continue
        return False

    hay = _normalize_str_set(hay_values)
    needles = _normalize_str_set(needle_values)
    if not hay or not needles:
        return False

    if mode == "exact":
        return bool(hay.intersection(needles))

    for needle in needles:
        for item in hay:
            if needle in item or item in needle:
                return True
    return False


def discover_validators(package_name: str = "zentry.validators", auth_manager: Any = None) -> List[Any]:
    """Discover validator classes dynamically using pkgutil/importlib."""
    package = importlib.import_module(package_name)
    discovered: List[Any] = []

    for module_info in pkgutil.iter_modules(package.__path__, f"{package_name}."):
        module_name = module_info.name
        if module_name.rsplit(".", 1)[-1].startswith("_"):
            continue

        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module.__name__:
                continue
            if not obj.__name__.endswith("Validator"):
                continue
            if not callable(getattr(obj, "can_run", None)):
                continue
            if not callable(getattr(obj, "run", None)):
                continue

            try:
                instance = obj(context=None, auth_manager=auth_manager)
            except TypeError:
                try:
                    instance = obj(auth_manager=auth_manager)
                except TypeError:
                    try:
                        instance = obj(context=None)
                        instance.auth_manager = auth_manager
                    except TypeError:
                        try:
                            instance = obj()
                            instance.auth_manager = auth_manager
                        except Exception:
                            continue
                    except Exception:
                        continue
                except Exception:
                    continue
            except Exception:
                continue

            if not hasattr(instance, "SIGNALS"):
                setattr(instance, "SIGNALS", {})
            discovered.append(instance)

    # Deterministic output before selection.
    discovered.sort(key=lambda v: v.__class__.__name__.lower())
    return discovered


def select_validators(
    signal_bag: Dict[str, List[Any]],
    validators: List[Any],
    return_reasons: bool = False,
) -> Union[List[Any], Tuple[List[Any], Dict[str, List[str]]]]:
    """Select matching validators based on SIGNALS and sort by priority descending."""
    selected: List[Any] = []
    reasons: Dict[str, List[str]] = {}

    for validator in validators:
        signals = getattr(validator, "SIGNALS", None)
        if not isinstance(signals, dict):
            signals = {}

        if not signals:
            selected.append(validator)
            reasons[validator.__class__.__name__] = ["universal_validator"]
            continue

        matched = False
        match_reasons: List[str] = []

        param_patterns = _safe_iter(signals.get("param_patterns"))
        if _match_signal_values(param_patterns, signal_bag.get("param_patterns", []), mode="exact"):
            matched = True
            match_reasons.append("param_patterns")

        endpoint_patterns = _safe_iter(signals.get("endpoint_patterns"))
        if _match_signal_values(endpoint_patterns, signal_bag.get("endpoint_patterns", []), mode="contains"):
            matched = True
            match_reasons.append("endpoint_patterns")

        header_patterns = _safe_iter(signals.get("header_patterns"))
        if _match_signal_values(header_patterns, signal_bag.get("header_patterns", []), mode="contains"):
            matched = True
            match_reasons.append("header_patterns")

        fact_patterns = _safe_iter(signals.get("facts"))
        if _match_signal_values(fact_patterns, signal_bag.get("facts", []), mode="contains"):
            matched = True
            match_reasons.append("facts")

        port_patterns = _safe_iter(signals.get("ports"))
        if _match_signal_values(port_patterns, signal_bag.get("ports", []), mode="int"):
            matched = True
            match_reasons.append("ports")

        tech_patterns = _safe_iter(signals.get("tech"))
        if _match_signal_values(tech_patterns, signal_bag.get("tech", []), mode="contains"):
            matched = True
            match_reasons.append("tech")

        if matched:
            selected.append(validator)
            reasons[validator.__class__.__name__] = match_reasons or ["signal_match"]

    selected.sort(key=lambda v: int(getattr(v, "priority", 0) or 0), reverse=True)
    if return_reasons:
        return selected, reasons
    return selected


class ValidatorRegistry:
    """
    Class-based facade over the validator discovery/selection system.

    Used by ReconOrchestrator to discover, select, and invoke validators.
    """

    def __init__(self):
        # Auto-discover validators on creation
        auto_discover()
        self._validators = None

    def _ensure_discovered(self, auth_manager=None):
        if self._validators is None:
            self._validators = discover_validators(auth_manager=auth_manager)
        return self._validators

    def get_validator_by_vuln_type(self, vuln_type: str):
        """Return a registered validator function for the given vuln_type."""
        return VALIDATOR_REGISTRY.get(vuln_type)

    def infer_vuln_types(self, param: str, nuclei_tags=None) -> list:
        """Heuristic mapping from parameter name + nuclei tags to validator types."""
        return infer_vuln_types(param, nuclei_tags=nuclei_tags)

    def select_validators(self, signal_bag: Dict[str, List], auth_manager=None) -> Tuple[List, Dict[str, List[str]]]:
        """Discover and select validators based on runtime signals."""
        validators = discover_validators(auth_manager=auth_manager)
        selected, reasons = select_validators(
            signal_bag, validators, return_reasons=True
        )
        return selected, reasons
