from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any, Dict, Iterable, List, Tuple, Union


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


def discover_validators(package_name: str = "modules.pipeline.validators") -> List[Any]:
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
                instance = obj(context=None)
            except TypeError:
                try:
                    instance = obj()
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
