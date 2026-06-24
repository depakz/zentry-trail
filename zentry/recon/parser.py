"""Input sanitization and httpx JSON output parsing."""
import json
import re
from typing import Iterable

# Valid domain regex (RFC 1035-ish, allows subdomains)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*(?:\:\d{1,5})?$"
)


def sanitize_domains(raw: Iterable[str]) -> list[str]:
    """
    Clean a list of domains:
      - strip whitespace
      - drop wildcards (*.example.com)
      - drop schemes/paths
      - lowercase
      - deduplicate
      - validate format
    """
    cleaned: set[str] = set()
    for item in raw:
        if not item:
            continue
        d = item.strip().lower()
        # Strip scheme
        d = re.sub(r"^https?://", "", d)
        # Strip path
        d = d.split("/")[0]
        # Strip wildcard
        if d.startswith("*."):
            d = d[2:]
        if d.startswith("."):
            d = d[1:]
        # Validate
        if DOMAIN_RE.match(d):
            cleaned.add(d)
    return sorted(cleaned)


def parse_httpx_line(line: str) -> dict | None:
    """Parse a single JSON line from httpx output. Return None if invalid."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        j = json.loads(line)
    except json.JSONDecodeError:
        return None

    # httpx field map (handles different httpx versions)
    return {
        "url":          j.get("url") or j.get("input"),
        "input":        j.get("input"),
        "status":       j.get("status_code") or j.get("status-code"),
        "title":        (j.get("title") or "").strip(),
        "tech":         j.get("tech") or j.get("technologies") or [],
        "ip":           (j.get("a") or [j.get("host", "")])[0] if (j.get("a") or j.get("host")) else "",
        "host":         j.get("host"),
        "scheme":       j.get("scheme"),
        "webserver":    j.get("webserver", ""),
        "content_type": j.get("content_type") or j.get("content-type", ""),
        "content_length": j.get("content_length") or j.get("content-length", 0),
        "cdn":          j.get("cdn", False),
        "cdn_name":     j.get("cdn_name", ""),
    }


def parse_httpx_output(raw: str) -> list[dict]:
    """Parse full httpx stdout. Skip malformed lines silently."""
    results = []
    for line in raw.splitlines():
        parsed = parse_httpx_line(line)
        if parsed and parsed.get("url"):
            results.append(parsed)
    return results
