"""
Tests for the evidence bundle file capture system.

Validates:
  - Directory creation and graceful failure
  - File naming / slug rules
  - Credential redaction in saved files
  - PreparedRequest/Response capture
  - Evidence path propagation
  - SARIF evidence_bundle_path population
"""

import os
import re
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from core.evidence_collector import (
    EvidenceCollector,
    _slugify,
    _finding_filename,
    _redact_header_value,
    format_request_from_prepared,
    format_response_from_response,
    format_raw_request,
    format_raw_response,
    MAX_RESPONSE_BODY_BYTES,
)


class TestSlugify:
    """Part B — slugification rules."""

    def test_lowercase(self):
        assert _slugify("SQL-INJECTION") == "sql_injection"

    def test_non_alphanum_replaced(self):
        assert _slugify("/admin/clients.xls") == "admin_clients_xls"

    def test_consecutive_underscores_collapsed(self):
        assert _slugify("foo---bar___baz") == "foo_bar_baz"

    def test_truncation(self):
        long = "a" * 200
        assert len(_slugify(long)) <= 80

    def test_empty_returns_unknown(self):
        assert _slugify("") == "unknown"
        assert _slugify(None) == "unknown"


class TestFilename:
    """Part B — file naming convention."""

    def test_standard_naming(self):
        name = _finding_filename(1, "sensitive-file-exposure", "/admin/clients.xls", "req")
        assert name.startswith("finding_01_")
        assert name.endswith("_req.txt")
        assert "sensitive_file_exposure" in name
        assert "admin_clients_xls" in name

    def test_index_zero_padded(self):
        name = _finding_filename(7, "sql-injection", "/doLogin", "res")
        assert "finding_07_" in name
        assert "_res.txt" in name
        assert "sql_injection" in name
        assert "dologin" in name

    def test_compound_slug_truncated(self):
        name = _finding_filename(1, "a" * 50, "b" * 50, "req")
        # compound slug should be truncated to 80 chars
        parts = name.replace("finding_01_", "").replace("_req.txt", "")
        assert len(parts) <= 80


class TestCredentialRedaction:
    """Part C — security rules for credential redaction."""

    def test_authorization_redacted(self):
        assert _redact_header_value("Authorization", "Bearer token123") == "[REDACTED]"

    def test_cookie_redacted(self):
        assert _redact_header_value("Cookie", "session=abc123") == "[REDACTED]"

    def test_set_cookie_redacted(self):
        assert _redact_header_value("Set-Cookie", "token=xyz") == "[REDACTED]"

    def test_proxy_authorization_redacted(self):
        assert _redact_header_value("Proxy-Authorization", "Basic abc") == "[REDACTED]"

    def test_case_insensitive_redaction(self):
        assert _redact_header_value("AUTHORIZATION", "Bearer x") == "[REDACTED]"
        assert _redact_header_value("cookie", "sess=1") == "[REDACTED]"

    def test_normal_headers_not_redacted(self):
        assert _redact_header_value("Content-Type", "application/json") == "application/json"
        assert _redact_header_value("Host", "example.com") == "example.com"


class TestFormatFromRequests:
    """Part C — building raw HTTP text from requests objects."""

    def test_format_request_from_prepared(self):
        req = requests.Request(
            "POST",
            "http://altoro.testfire.net/doLogin",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "zentry-trail/1.0",
                "Authorization": "Bearer secret-token",
                "Cookie": "session=abc123",
            },
            data="uid=admin&passw=test",
        )
        prepared = req.prepare()

        text = format_request_from_prepared(prepared)

        assert "POST /doLogin HTTP/1.1" in text
        assert "Host: altoro.testfire.net" in text
        assert "Content-Type: application/x-www-form-urlencoded" in text
        assert "uid=admin&passw=test" in text
        # Credentials must be redacted
        assert "secret-token" not in text
        assert "abc123" not in text
        assert "[REDACTED]" in text

    def test_format_response_from_response(self):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.reason = "OK"
        resp.headers = {
            "Content-Type": "text/html",
            "Set-Cookie": "session=xyz789",
        }
        resp.content = b"<html>Hello World</html>"

        text = format_response_from_response(resp)

        assert "HTTP/1.1 200 OK" in text
        assert "Content-Type: text/html" in text
        assert "<html>Hello World</html>" in text
        # Set-Cookie value must be redacted
        assert "xyz789" not in text
        assert "[REDACTED]" in text

    def test_response_body_truncated_to_8192(self):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.reason = "OK"
        resp.headers = {}
        resp.content = b"x" * 20000

        text = format_response_from_response(resp)

        # The body is the content after the first double-newline separator.
        # Strip leading whitespace that comes from the blank separator line.
        body_part = text.split("\n\n", 1)[1].strip() if "\n\n" in text else ""
        assert len(body_part) <= MAX_RESPONSE_BODY_BYTES

    def test_none_request_returns_empty(self):
        assert format_request_from_prepared(None) == ""

    def test_none_response_returns_empty(self):
        assert format_response_from_response(None) == ""


class TestEvidenceCollector:
    """Parts A, B, C — directory creation, file writing, path injection."""

    def test_directory_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = EvidenceCollector(base_dir=tmp, scan_timestamp="2026-06-21_21-52-45")
            assert collector._ensure_dir() is True
            assert collector.evidence_dir.exists()
            assert collector.evidence_dir.name == "2026-06-21_21-52-45"

    def test_directory_creation_failure_graceful(self):
        """If directory creation fails, it should not crash."""
        collector = EvidenceCollector(base_dir="/nonexistent/root/path/123")
        assert collector._ensure_dir() is False

    def test_save_evidence_creates_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = EvidenceCollector(base_dir=tmp, scan_timestamp="test_run")

            findings = [
                {
                    "vulnerability": "sql-injection",
                    "target_url": "http://altoro.testfire.net/doLogin",
                    "payload": "' OR '1'='1",
                    "method": "POST",
                    "response_snippet": "<html>Error in SQL</html>",
                    "_evidence_response_status": 500,
                    "_evidence_response_headers": {"Content-Type": "text/html"},
                    "_evidence_request_headers": {"User-Agent": "zentry-trail/1.0"},
                },
            ]

            collector.save_evidence(findings)

            # Check evidence dir exists
            assert collector.evidence_dir.exists()

            # Check files were created
            files = list(collector.evidence_dir.iterdir())
            assert len(files) == 2

            # Check filenames
            filenames = sorted(f.name for f in files)
            assert any("_req.txt" in f for f in filenames)
            assert any("_res.txt" in f for f in filenames)

            # Check paths injected into finding dict
            assert findings[0]["evidence_req_path"] != ""
            assert findings[0]["evidence_res_path"] != ""

    def test_save_evidence_multiple_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = EvidenceCollector(base_dir=tmp, scan_timestamp="multi")

            findings = [
                {"vulnerability": "sql-injection", "target_url": "http://example.com/login", "method": "POST", "payload": "test"},
                {"vulnerability": "xss", "target_url": "http://example.com/search", "method": "GET", "payload": "<script>"},
                {"vulnerability": "open-redirect", "target_url": "http://example.com/redir", "method": "GET", "payload": "http://evil.com"},
            ]

            collector.save_evidence(findings)

            files = list(collector.evidence_dir.iterdir())
            assert len(files) == 6  # 2 files per finding

    def test_save_single_evidence_with_requests_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = EvidenceCollector(base_dir=tmp, scan_timestamp="single")

            req = requests.Request(
                "POST",
                "http://target.com/api",
                headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
                data='{"user": "admin"}',
            )
            prepared = req.prepare()

            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.reason = "OK"
            resp.headers = {"Content-Type": "application/json", "Set-Cookie": "session=tok123"}
            resp.content = b'{"result": "success"}'

            paths = collector.save_single_evidence(
                index=1,
                vuln="sql-injection",
                endpoint="http://target.com/api",
                prepared_request=prepared,
                response_obj=resp,
            )

            assert paths["evidence_req_path"] != ""
            assert paths["evidence_res_path"] != ""

            # Verify credential redaction in req file
            req_content = Path(paths["evidence_req_path"]).read_text()
            assert "secret" not in req_content
            assert "[REDACTED]" in req_content

            # Verify credential redaction in res file
            res_content = Path(paths["evidence_res_path"]).read_text()
            assert "tok123" not in res_content
            assert "[REDACTED]" in res_content

    def test_failed_dir_sets_empty_paths(self):
        collector = EvidenceCollector(base_dir="/nonexistent/root")
        findings = [{"vulnerability": "xss", "target_url": "http://test.com"}]
        collector.save_evidence(findings)
        assert findings[0]["evidence_req_path"] == ""
        assert findings[0]["evidence_res_path"] == ""


class TestSarifEvidencePropagation:
    """Part E — evidence_bundle_path in SARIF output."""

    def test_sarif_builder_includes_evidence_path(self):
        from avvp.libs.sarif_schema import sarif_builder

        findings = [
            {
                "vulnerability": "sql-injection",
                "severity": "high",
                "uri": "http://example.com/login",
                "payload": "' OR 1=1",
                "evidence_req_path": "_output/evidence/2026-06-21_21-52-45/finding_01_sql_injection_login_req.txt",
            },
        ]

        sarif = sarif_builder.build_sarif_report(findings)
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["evidence_bundle_path"] != ""
        assert "finding_01" in result["properties"]["evidence_bundle_path"]

    def test_sarif_reporter_includes_evidence_path(self):
        from core.sarif_reporter import SARIFReporter

        reporter = SARIFReporter()
        findings = [
            {
                "vulnerability": "open-redirect",
                "severity": "high",
                "target_url": "http://example.com/redir",
                "payload": "http://evil.com",
                "cvss": 8.5,
                "evidence_req_path": "_output/evidence/test/finding_01_req.txt",
                "evidence_res_path": "_output/evidence/test/finding_01_res.txt",
            },
        ]

        sarif = reporter.generate(findings=findings, target="http://example.com")
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["evidence_bundle_path"] == "_output/evidence/test/finding_01_req.txt"


class TestLegacyFormatting:
    """Ensure legacy format_raw_request / format_raw_response still work."""

    def test_format_raw_request_from_dict(self):
        finding = {
            "target_url": "http://test.com/api",
            "payload": "test-payload",
            "method": "GET",
            "_evidence_request_headers": {"Authorization": "Bearer xyz"},
        }
        text = format_raw_request(finding)
        assert "GET /api HTTP/1.1" in text
        assert "Host: test.com" in text
        # Authorization should be redacted
        assert "xyz" not in text
        assert "[REDACTED]" in text

    def test_format_raw_response_from_dict(self):
        finding = {
            "_evidence_response_status": 403,
            "response_snippet": "Access Denied",
            "_evidence_response_headers": {"Cookie": "session=secret"},
        }
        text = format_raw_response(finding)
        assert "HTTP/1.1 403" in text
        assert "Access Denied" in text
        assert "secret" not in text
        assert "[REDACTED]" in text
