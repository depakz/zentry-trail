"""
Evidence bundle collector for zentry-trail.

Captures raw HTTP request/response pairs for every confirmed finding and
saves them to disk as plain-text files.  Paths are injected back into the
finding dicts so that report outputs (SARIF, JSON, HTML, PDF) can
reference the evidence.

Directory layout:
    _output/evidence/{scan_timestamp}/
        finding_01_sql_injection_dologin_req.txt
        finding_01_sql_injection_dologin_res.txt
        ...

Security: Authorization and Cookie header values are redacted before
writing to prevent credential leakage.
"""

from __future__ import annotations

import re
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests as _requests_mod  # for type hints only

logger = logging.getLogger("zentry.evidence")

# ── Constants ────────────────────────────────────────────────────────────────
MAX_SLUG_LENGTH = 80
MAX_RESPONSE_BODY_BYTES = 8192
MAX_RESPONSE_DISPLAY_BYTES = 2048  # For HTML report inline display

# Headers whose values must be redacted before writing to disk
_SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie"}


# ── Slug helpers ─────────────────────────────────────────────────────────────

def _slugify(text: str, max_len: int = MAX_SLUG_LENGTH) -> str:
    """
    Convert arbitrary text to a filesystem-safe slug.

    Rules (per spec):
    - Lowercase everything
    - Replace all non-alphanumeric characters with underscore
    - Collapse consecutive underscores to one
    - Truncate to max_len characters
    """
    slug = str(text or "").lower()
    slug = re.sub(r"[^a-z0-9]", "_", slug)
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug[:max_len] if slug else "unknown"


def _endpoint_slug(url: str) -> str:
    """Extract a slug from a URL path (ignoring scheme/host/query)."""
    try:
        path = urlparse(url).path or ""
    except Exception:
        path = str(url)
    return _slugify(path)


def _vuln_slug(vulnerability: str) -> str:
    """Convert a vulnerability name to a slug."""
    return _slugify(vulnerability)


def _finding_filename(index: int, vuln: str, endpoint: str, suffix: str) -> str:
    """
    Build a filename for an evidence file.

    Format: finding_{index:02d}_{vuln_slug}_{endpoint_slug}_{suffix}.txt
    The combined vuln+endpoint slug is truncated to MAX_SLUG_LENGTH.
    """
    vs = _vuln_slug(vuln)
    es = _endpoint_slug(endpoint)
    # Combine and truncate the compound slug
    compound = f"{vs}_{es}"
    compound = re.sub(r"_+", "_", compound).strip("_")
    compound = compound[:MAX_SLUG_LENGTH]
    return f"finding_{index:02d}_{compound}_{suffix}.txt"


# ── Credential redaction ────────────────────────────────────────────────────

def _redact_header_value(name: str, value: str) -> str:
    """Replace sensitive header values with [REDACTED]."""
    if name.lower() in _SENSITIVE_HEADERS:
        return "[REDACTED]"
    return value


def _redact_headers_dict(headers: dict) -> dict:
    """Return a copy of headers with sensitive values redacted."""
    return {k: _redact_header_value(k, v) for k, v in headers.items()}


# ── Raw HTTP formatting from requests objects ────────────────────────────────

def format_request_from_prepared(prepared: "_requests_mod.PreparedRequest") -> str:
    """
    Build the full raw HTTP request text from a requests.PreparedRequest.

    Redacts Authorization and Cookie header values.
    """
    if prepared is None:
        return ""

    try:
        parsed = urlparse(prepared.url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        request_line = f"{prepared.method} {path} HTTP/1.1"

        headers = dict(prepared.headers or {})
        # Ensure Host header is present
        if "Host" not in headers and parsed.netloc:
            headers = {"Host": parsed.netloc, **headers}

        header_lines = [f"{k}: {_redact_header_value(k, v)}" for k, v in headers.items()]
        header_text = "\n".join(header_lines)

        body_text = ""
        if prepared.body:
            if isinstance(prepared.body, bytes):
                body_text = prepared.body.decode("utf-8", errors="replace")
            else:
                body_text = str(prepared.body)

        return f"{request_line}\n{header_text}\n\n{body_text}"
    except Exception as exc:
        logger.debug("Failed to format PreparedRequest: %s", exc)
        return ""


def format_response_from_response(response: "_requests_mod.Response") -> str:
    """
    Build the full raw HTTP response text from a requests.Response.

    Body is truncated to MAX_RESPONSE_BODY_BYTES (8192) and decoded
    with errors='replace'.  Sensitive header values are redacted.
    """
    if response is None:
        return ""

    try:
        reason = response.reason or "OK"
        status_line = f"HTTP/1.1 {response.status_code} {reason}"

        header_lines = [
            f"{k}: {_redact_header_value(k, v)}"
            for k, v in response.headers.items()
        ]
        header_text = "\n".join(header_lines)

        # Truncate body to 8192 bytes, decoded with errors=replace
        body_text = ""
        if response.content is not None:
            raw_bytes = response.content[:MAX_RESPONSE_BODY_BYTES]
            body_text = raw_bytes.decode("utf-8", errors="replace")

        return f"{status_line}\n{header_text}\n\n{body_text}"
    except Exception as exc:
        logger.debug("Failed to format Response: %s", exc)
        return ""


# ── Legacy raw HTTP formatting from finding dicts ────────────────────────────

def format_raw_request(finding: Dict[str, Any]) -> str:
    """
    Reconstruct a raw HTTP request from a finding dict, or use pre-captured raw_request.

    Uses fields: raw_request, target_url, payload, method (defaults to GET),
    and any available header info from the evidence blob.
    """
    if finding.get("raw_request"):
        return str(finding["raw_request"])

    url = str(finding.get("target_url") or finding.get("url") or finding.get("endpoint") or "")
    payload = str(finding.get("payload") or "")
    method = str(finding.get("method") or "GET").upper()

    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
    except Exception:
        host = ""
        path = url

    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {host}")
    lines.append("User-Agent: zentry-trail/1.0")

    # Add content-type for POST
    if method == "POST" and payload:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(payload)}")

    # Add any extra headers from evidence blob (redacted)
    evidence_headers = finding.get("_evidence_request_headers")
    if isinstance(evidence_headers, dict):
        for k, v in evidence_headers.items():
            if k.lower() not in ("host", "content-type", "content-length", "user-agent"):
                lines.append(f"{k}: {_redact_header_value(k, v)}")

    lines.append("")  # blank line before body

    if method == "POST" and payload:
        lines.append(payload)
    elif method == "GET" and payload:
        # For GET, payload may be in the query string already
        lines.append(f"# Injected payload: {payload}")

    return "\n".join(lines)


def format_raw_response(finding: Dict[str, Any]) -> str:
    """
    Reconstruct a raw HTTP response from a finding dict, or use pre-captured raw_response.

    Uses fields: raw_response, response_snippet, _evidence_response_status,
    _evidence_response_headers.  Truncates body to MAX_RESPONSE_BODY_BYTES.
    """
    if finding.get("raw_response"):
        return str(finding["raw_response"])

    status = finding.get("_evidence_response_status") or 200
    snippet = str(finding.get("response_snippet") or finding.get("evidence") or "")

    lines = [f"HTTP/1.1 {status} OK"]

    # Add response headers if available (redacted)
    resp_headers = finding.get("_evidence_response_headers")
    if isinstance(resp_headers, dict):
        for k, v in resp_headers.items():
            lines.append(f"{k}: {_redact_header_value(k, v)}")

    lines.append("")  # blank line before body
    lines.append(snippet[:MAX_RESPONSE_BODY_BYTES])

    return "\n".join(lines)


# ── Evidence Collector ───────────────────────────────────────────────────────

class EvidenceCollector:
    """
    Writes raw HTTP evidence files to disk for confirmed findings.

    Usage:
        collector = EvidenceCollector("_output/evidence")
        collector.save_evidence(findings_list)
        # Each finding dict now has evidence_req_path / evidence_res_path
    """

    def __init__(self, base_dir: str = "_output/evidence", scan_timestamp: Optional[str] = None):
        self.scan_timestamp = scan_timestamp or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.evidence_dir = Path(base_dir) / self.scan_timestamp
        self._created = False

    def _ensure_dir(self) -> bool:
        """
        Create the evidence directory.  Returns True on success.

        Non-fatal: if creation fails, logs a warning and returns False.
        """
        if self._created:
            return True
        try:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            self._created = True
            return True
        except Exception as exc:
            logger.warning("WARNING: evidence capture disabled — %s", exc)
            return False

    def save_single_evidence(
        self,
        index: int,
        vuln: str,
        endpoint: str,
        prepared_request: Optional["_requests_mod.PreparedRequest"] = None,
        response_obj: Optional["_requests_mod.Response"] = None,
        raw_request_text: str = "",
        raw_response_text: str = "",
    ) -> Dict[str, str]:
        """
        Save evidence for a single finding at confirmation time.

        Accepts either requests objects (PreparedRequest / Response) or
        pre-formatted text strings.  Returns dict with evidence_req_path
        and evidence_res_path (relative to cwd), or empty strings on failure.

        Parameters
        ----------
        index : int
            1-based finding index for filename.
        vuln : str
            Vulnerability type (e.g. "sql-injection").
        endpoint : str
            Target URL.
        prepared_request : requests.PreparedRequest, optional
            The actual request object.
        response_obj : requests.Response, optional
            The actual response object.
        raw_request_text : str
            Pre-formatted request text (used if no PreparedRequest given).
        raw_response_text : str
            Pre-formatted response text (used if no Response given).

        Returns
        -------
        dict with "evidence_req_path" and "evidence_res_path".
        """
        if not self._ensure_dir():
            return {"evidence_req_path": "", "evidence_res_path": ""}

        req_filename = _finding_filename(index, vuln, endpoint, "req")
        res_filename = _finding_filename(index, vuln, endpoint, "res")

        req_path = self.evidence_dir / req_filename
        res_path = self.evidence_dir / res_filename

        # Build request content
        req_content = ""
        if prepared_request is not None:
            req_content = format_request_from_prepared(prepared_request)
        if not req_content:
            req_content = raw_request_text

        # Build response content
        res_content = ""
        if response_obj is not None:
            res_content = format_response_from_response(response_obj)
        if not res_content:
            res_content = raw_response_text

        # Write request
        try:
            req_path.write_text(req_content, encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to write evidence request for finding %d: %s", index, exc)
            req_path = None

        # Write response
        try:
            res_path.write_text(res_content, encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to write evidence response for finding %d: %s", index, exc)
            res_path = None

        result = {}
        try:
            result["evidence_req_path"] = str(req_path.relative_to(Path.cwd())) if req_path and req_path.exists() else ""
        except ValueError:
            result["evidence_req_path"] = str(req_path) if req_path and req_path.exists() else ""
        try:
            result["evidence_res_path"] = str(res_path.relative_to(Path.cwd())) if res_path and res_path.exists() else ""
        except ValueError:
            result["evidence_res_path"] = str(res_path) if res_path and res_path.exists() else ""

        return result

    def save_evidence(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Save raw HTTP evidence files for each finding and inject paths.

        For each finding in the list:
          - Writes a *_req.txt file with the raw HTTP request
          - Writes a *_res.txt file with the status + headers + body[:8192]
          - Sets finding["evidence_req_path"] and finding["evidence_res_path"]

        Parameters
        ----------
        findings : list[dict]
            Deduplicated findings list (mutated in-place with paths added).

        Returns
        -------
        list[dict]
            The same list, with evidence_req_path / evidence_res_path set.
        """
        if not findings:
            return findings

        if not self._ensure_dir():
            # Non-fatal: set empty paths and continue
            for finding in findings:
                finding.setdefault("evidence_req_path", "")
                finding.setdefault("evidence_res_path", "")
            return findings

        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue

            # Skip if evidence paths already populated (e.g. from confirm-time capture)
            if finding.get("evidence_req_path") and finding.get("evidence_res_path"):
                continue

            vuln = str(finding.get("vulnerability") or finding.get("title") or "unknown")
            endpoint = str(finding.get("target_url") or finding.get("endpoint") or "unknown")

            # Generate filenames
            req_filename = _finding_filename(index, vuln, endpoint, "req")
            res_filename = _finding_filename(index, vuln, endpoint, "res")

            req_path = self.evidence_dir / req_filename
            res_path = self.evidence_dir / res_filename

            try:
                req_content = format_raw_request(finding)
                req_path.write_text(req_content, encoding="utf-8")
            except Exception as exc:
                logger.warning("Failed to write evidence request for finding %d: %s", index, exc)
                req_path = None

            try:
                res_content = format_raw_response(finding)
                res_path.write_text(res_content, encoding="utf-8")
            except Exception as exc:
                logger.warning("Failed to write evidence response for finding %d: %s", index, exc)
                res_path = None

            # Inject relative paths into the finding dict
            try:
                finding["evidence_req_path"] = str(req_path.relative_to(Path.cwd())) if req_path and req_path.exists() else ""
            except ValueError:
                finding["evidence_req_path"] = str(req_path) if req_path and req_path.exists() else ""
            try:
                finding["evidence_res_path"] = str(res_path.relative_to(Path.cwd())) if res_path and res_path.exists() else ""
            except ValueError:
                finding["evidence_res_path"] = str(res_path) if res_path and res_path.exists() else ""

        return findings

    @property
    def directory(self) -> Path:
        """Return the evidence directory path."""
        return self.evidence_dir
