from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import parse_qsl, urlsplit

from modules.pipeline.brain.fact_store import FactCategory, FactStore


_TECH_PATTERNS = {
    "wordpress": ("wp-content", "wp-includes", "wordpress"),
    "laravel": ("laravel_session", "laravel"),
    "nextjs": ("__next", "next.js", "nextjs"),
    "php": ("php",),
    "nginx": ("nginx",),
    "react": ("react",),
    "django": ("django", "csrftoken"),
    "graphql": ("graphql",),
}

_ENDPOINT_HINTS = [
    "/graphql",
    "/api/graphql",
    "/__graphql",
    "/gql",
    "/login",
    "/signin",
    "/auth",
    "/session",
    "/account",
    "/upload",
    "/import",
    "/parse",
    "/process",
    "/api",
    "/admin",
    "/dashboard",
    "/profile",
    "/comment",
    "/post",
    "/review",
    "/message",
    "/checkout",
    "/payment",
    "/order",
    "/transfer",
    "/coupon",
    "/redeem",
    "/claim",
]

_HEADER_KEYS = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-powered-by",
    "server",
    "content-type",
)


def _coerce_port_results(port_results: Any) -> Dict[str, Any]:
    if isinstance(port_results, dict):
        return port_results
    if isinstance(port_results, str):
        candidate = Path(port_results)
        if candidate.exists() and candidate.is_file():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                return {}
    return {}


def _iter_header_values(headers: Any) -> Iterable[str]:
    if isinstance(headers, dict):
        for key, value in headers.items():
            key_s = str(key or "").strip()
            value_s = str(value or "").strip()
            if not key_s and not value_s:
                continue
            if key_s:
                yield f"{key_s}: {value_s}"
            else:
                yield value_s
    elif isinstance(headers, list):
        for item in headers:
            if isinstance(item, str) and item.strip():
                yield item.strip()


def _extract_ports(port_results: Dict[str, Any]) -> List[int]:
    ports: Set[int] = set()
    for entry in port_results.get("open_ports", []) or []:
        if not isinstance(entry, dict):
            continue
        value = entry.get("port")
        try:
            if value is not None:
                ports.add(int(value))
        except Exception:
            continue
    return sorted(ports)


def _extract_param_patterns(endpoints: Iterable[str]) -> List[str]:
    params: Set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue
        try:
            parsed = urlsplit(endpoint)
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                key = (key or "").strip().lower()
                if key:
                    params.add(key)
        except Exception:
            continue
    return sorted(params)


def _extract_endpoint_patterns(endpoints: Iterable[str]) -> List[str]:
    patterns: Set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue
        low = endpoint.lower()
        try:
            path = urlsplit(endpoint).path.lower() or "/"
            if path:
                parts = [part for part in path.split("/") if part]
                if parts:
                    patterns.add(f"/{parts[0]}")
                if len(parts) > 1:
                    patterns.add("/" + "/".join(parts[:2]))
        except Exception:
            pass
        for hint in _ENDPOINT_HINTS:
            if hint in low:
                patterns.add(hint)
    return sorted(patterns)


def _extract_tech(alive_hosts: Iterable[Any], endpoints: Iterable[str], header_values: Iterable[str]) -> List[str]:
    tech: Set[str] = set()

    corpus: List[str] = []
    for host in alive_hosts:
        if isinstance(host, dict):
            for key in ("url", "title", "webserver", "content_type", "scheme"):
                value = host.get(key)
                if isinstance(value, str):
                    corpus.append(value)
            tvals = host.get("tech")
            if isinstance(tvals, list):
                for item in tvals:
                    if isinstance(item, str):
                        corpus.append(item)

    for endpoint in endpoints:
        if isinstance(endpoint, str):
            corpus.append(endpoint)

    for header in header_values:
        corpus.append(header)

    joined = "\n".join(corpus).lower()
    for tech_name, tokens in _TECH_PATTERNS.items():
        if any(token in joined for token in tokens):
            tech.add(tech_name)

    # Prefer preserving explicit tech tags when available.
    for host in alive_hosts:
        if not isinstance(host, dict):
            continue
        tvals = host.get("tech")
        if isinstance(tvals, list):
            for item in tvals:
                if isinstance(item, str) and item.strip():
                    tech.add(item.strip().lower())

    return sorted(tech)


def _extract_header_patterns(headers: Any, alive_hosts: Iterable[Any]) -> List[str]:
    patterns: Set[str] = set()

    for header_line in _iter_header_values(headers):
        low = header_line.lower()
        if "bearer" in low:
            patterns.add("Bearer")
            patterns.add("Authorization: Bearer")
        if "jwt" in low:
            patterns.add("JWT")
            patterns.add("jwt")
        if "x-powered-by" in low and "php" in low:
            patterns.add("X-Powered-By: PHP")
        if low.startswith("content-type:"):
            if "application/xml" in low:
                patterns.add("application/xml")
            if "text/xml" in low:
                patterns.add("text/xml")
            if "application/octet-stream" in low:
                patterns.add("application/octet-stream")
            if "application/x-java-serialized" in low:
                patterns.add("application/x-java-serialized")

        if low.startswith("set-cookie:") or low.startswith("cookie:"):
            cookie_blob = low.split(":", 1)[-1]
            for cookie_piece in cookie_blob.split(";"):
                cookie_piece = cookie_piece.strip()
                if not cookie_piece:
                    continue
                if "." in cookie_piece and "=" in cookie_piece:
                    _, cval = cookie_piece.split("=", 1)
                    if cval.count(".") >= 1:
                        patterns.add("JWT")
                        patterns.add("jwt")
                if cookie_piece.startswith("laravel_session"):
                    patterns.add("laravel_session")

    for host in alive_hosts:
        if not isinstance(host, dict):
            continue
        webserver = host.get("webserver")
        if isinstance(webserver, str) and webserver.strip():
            patterns.add(f"Server: {webserver.strip()}")

    return sorted(patterns)


def _extract_facts(fact_store: Optional[FactStore]) -> List[str]:
    store = fact_store or FactStore()
    out: Set[str] = set()
    for fact in store.get_facts_by_category(FactCategory.CONFIRMED_VULNERABILITY):
        if fact.key:
            out.add(str(fact.key))
        value = fact.value if isinstance(fact.value, dict) else {}
        vuln_type = value.get("type")
        if isinstance(vuln_type, str) and vuln_type.strip():
            out.add(vuln_type.strip())
    return sorted(out)


def extract_signals(
    alive_hosts: Iterable[Any],
    port_results: Any,
    endpoints: Iterable[str],
    headers: Any,
    fact_store: Optional[FactStore] = None,
) -> Dict[str, List[Any]]:
    """Extract structured runtime signals from recon artifacts for validator routing."""
    port_data = _coerce_port_results(port_results)
    endpoint_list = [ep for ep in endpoints if isinstance(ep, str)]

    header_lines = list(_iter_header_values(headers))
    for host in alive_hosts:
        if isinstance(host, dict):
            for key in ("webserver", "content_type"):
                value = host.get(key)
                if isinstance(value, str) and value.strip():
                    header_lines.append(f"{key}: {value}")

    signal_bag: Dict[str, List[Any]] = {
        "tech": _extract_tech(alive_hosts, endpoint_list, header_lines),
        "ports": _extract_ports(port_data),
        "param_patterns": _extract_param_patterns(endpoint_list),
        "endpoint_patterns": _extract_endpoint_patterns(endpoint_list),
        "header_patterns": _extract_header_patterns(headers, alive_hosts),
        "facts": _extract_facts(fact_store),
    }

    return signal_bag
