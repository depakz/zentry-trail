from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List


PAYLOAD_CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "sql-injection": [
        {
            "id_suffix": "sqli-basic",
            "info": {"name": "SQL Injection Boolean Probe", "severity": "high", "tags": ["sqli", "boolean", "db"]},
            "payload_path": "/?q=1' OR '1'='1",
            "method": "GET",
            "matchers": ["syntax error", "mysql", "postgresql"],
        },
        {
            "id_suffix": "sqli-time",
            "info": {"name": "SQL Injection Time Probe", "severity": "high", "tags": ["sqli", "time-based"]},
            "payload_path": "/search?q=1' OR SLEEP(5)-- -",
            "method": "GET",
            "matchers": ["timeout", "sleep", "delay"],
        },
    ],
    "xss": [
        {
            "id_suffix": "xss-reflect",
            "info": {"name": "Reflected XSS Probe", "severity": "high", "tags": ["xss", "reflected"]},
            "payload_path": "/?q=<script>alert(1)</script>",
            "method": "GET",
            "matchers": ["<script>alert(1)</script>", "alert(1)"],
        },
        {
            "id_suffix": "xss-dom",
            "info": {"name": "DOM XSS Probe", "severity": "medium", "tags": ["xss", "dom"]},
            "payload_path": "/search#<img src=x onerror=alert(1)>",
            "method": "GET",
            "matchers": ["onerror", "alert(1)"],
        },
        {
            "id_suffix": "xss-stored",
            "info": {"name": "Stored XSS Probe", "severity": "high", "tags": ["xss", "stored"]},
            "payload_path": "/comment?body=<svg/onload=alert(1)>",
            "method": "POST",
            "matchers": ["<svg", "alert(1)"],
        },
    ],
    "auth": [
        {
            "id_suffix": "admin-panel",
            "info": {"name": "Admin Panel Discovery", "severity": "medium", "tags": ["auth", "exposure"]},
            "payload_path": "/admin/",
            "method": "GET",
            "matchers": ["admin", "dashboard"],
        },
        {
            "id_suffix": "dir-traversal",
            "info": {"name": "Path Traversal Probe", "severity": "high", "tags": ["auth", "traversal"]},
            "payload_path": "/..%2f..%2fetc/passwd",
            "method": "GET",
            "matchers": ["root:x:", "bin/bash"],
        },
    ],
    "headers": [
        {
            "id_suffix": "cors-misconfig",
            "info": {"name": "CORS Wildcard Misconfiguration", "severity": "medium", "tags": ["headers", "cors"]},
            "payload_path": "/",
            "method": "OPTIONS",
            "headers": {"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
            "matchers": ["access-control-allow-origin"],
        },
        {
            "id_suffix": "missing-security-headers",
            "info": {"name": "Missing Security Headers", "severity": "low", "tags": ["headers", "hardening"]},
            "payload_path": "/",
            "method": "GET",
            "matchers": ["content-security-policy", "x-frame-options"],
        },
    ],
    "open-redirect": [
        {
            "id_suffix": "or-redirect",
            "info": {"name": "Open Redirect Probe", "severity": "medium", "tags": ["redirect", "open-redirect"]},
            "payload_path": "/redirect?to=https://evil.example/",
            "method": "GET",
            "matchers": ["location", "evil.example"],
        },
        {
            "id_suffix": "or-next",
            "info": {"name": "Next Parameter Redirect", "severity": "medium", "tags": ["redirect", "next"]},
            "payload_path": "/login?next=https://evil.example/",
            "method": "GET",
            "matchers": ["location", "evil.example"],
        },
    ],
    "csrf": [
        {
            "id_suffix": "csrf-form",
            "info": {"name": "CSRF Token Missing", "severity": "medium", "tags": ["csrf", "form"]},
            "payload_path": "/profile/update",
            "method": "POST",
            "matchers": ["csrf", "token"],
        },
        {
            "id_suffix": "csrf-action",
            "info": {"name": "State Changing Action Without Token", "severity": "medium", "tags": ["csrf", "state-change"]},
            "payload_path": "/account/email/change",
            "method": "POST",
            "matchers": ["csrf", "forbidden"],
        },
    ],
    "lfi": [
        {
            "id_suffix": "lfi-basic",
            "info": {"name": "Local File Inclusion Probe", "severity": "high", "tags": ["lfi", "file-read"]},
            "payload_path": "/download?file=../../../../etc/passwd",
            "method": "GET",
            "matchers": ["root:x:", "daemon:"],
        },
        {
            "id_suffix": "lfi-nullbyte",
            "info": {"name": "Null Byte LFI Probe", "severity": "high", "tags": ["lfi", "legacy"]},
            "payload_path": "/view?path=../../../../etc/passwd%00",
            "method": "GET",
            "matchers": ["root:x:", "bin/bash"],
        },
    ],
    "ssrf": [
        {
            "id_suffix": "ssrf-loopback",
            "info": {"name": "Loopback SSRF Probe", "severity": "high", "tags": ["ssrf", "loopback"]},
            "payload_path": "/fetch?url=http://127.0.0.1/",
            "method": "GET",
            "matchers": ["connection refused", "localhost"],
        },
        {
            "id_suffix": "ssrf-metadata",
            "info": {"name": "Metadata SSRF Probe", "severity": "high", "tags": ["ssrf", "cloud"]},
            "payload_path": "/fetch?url=http://169.254.169.254/latest/meta-data/",
            "method": "GET",
            "matchers": ["ami-id", "instance-id"],
        },
    ],
    "ssti": [
        {
            "id_suffix": "ssti-basic",
            "info": {"name": "Server-Side Template Injection Probe", "severity": "high", "tags": ["ssti", "template"]},
            "payload_path": "/render?name={{7*7}}",
            "method": "GET",
            "matchers": ["49", "template"],
        },
        {
            "id_suffix": "ssti-alt",
            "info": {"name": "Template Expression Probe", "severity": "high", "tags": ["ssti", "expression"]},
            "payload_path": "/render?name=${7*7}",
            "method": "GET",
            "matchers": ["49", "expression"],
        },
    ],
    "jwt": [
        {
            "id_suffix": "jwt-none",
            "info": {"name": "JWT None Algorithm Probe", "severity": "high", "tags": ["jwt", "alg-none"]},
            "payload_path": "/api/profile",
            "method": "GET",
            "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."},
            "matchers": ["token", "unauthorized"],
        },
        {
            "id_suffix": "jwt-fixation",
            "info": {"name": "JWT Fixation Probe", "severity": "medium", "tags": ["jwt", "session"]},
            "payload_path": "/api/session",
            "method": "GET",
            "headers": {"Authorization": "Bearer {{JWT}}"},
            "matchers": ["session", "authorized"],
        },
    ],
}


def iter_catalog() -> Iterable[tuple[str, Dict[str, Any]]]:
    for category, examples in PAYLOAD_CATALOG.items():
        for example in examples:
            yield category, example


def template_record(category: str, example: Dict[str, Any], index: int) -> Dict[str, Any]:
    template_id = f"avvp-{category}-{example['id_suffix']}-{index}"
    info = dict(example.get("info", {}))
    info.setdefault("author", "avvp")
    info.setdefault("severity", "medium")
    info.setdefault("description", f"{info.get('name', template_id)} nuclei-style detection template.")
    info.setdefault("tags", [category])

    request: Dict[str, Any] = {
        "method": example.get("method", "GET"),
        "path": [example.get("payload_path", "{{BaseURL}}/")],
        "matchers": [
            {
                "type": "word",
                "words": example.get("matchers", [category]),
                "part": "body",
            }
        ],
    }
    if example.get("headers"):
        request["headers"] = example["headers"]
    if example.get("redirects") is not None:
        request["redirects"] = bool(example["redirects"])

    return {
        "id": template_id,
        "info": info,
        "metadata": {
            "category": category,
            "template_type": "detection",
            "source": "avvp",
        },
        "requests": [request],
    }


def library_index(base_dir: str | Path) -> Dict[str, Any]:
    base = Path(base_dir)
    categories: List[Dict[str, Any]] = []
    total = 0
    for category in sorted(p.name for p in base.iterdir() if p.is_dir()):
        files = sorted(base.joinpath(category).glob("*.yaml"))
        categories.append({"name": category, "count": len(files), "files": [f.name for f in files]})
        total += len(files)
    return {"count": total, "categories": categories}
