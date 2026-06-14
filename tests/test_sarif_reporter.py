"""
tests/test_sarif_reporter.py — Session 8 tests

Tests for core/sarif_reporter.py and avvp/libs/sarif_schema/sarif_builder.py
"""

import json
import pytest
from pathlib import Path

from core.sarif_reporter import SARIFReporter
from avvp.libs.sarif_schema.sarif_builder import build_sarif_report, validate_sarif


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockSession:
    """Minimal scan session for testing."""
    def __init__(self, findings=None, target="https://example.com", scan_id="scan-test-001"):
        self.findings = findings or []
        self.target   = target
        self.scan_id  = scan_id


def make_finding(vuln_class="xss", severity="high", url="https://example.com/search",
                 summary="Reflected XSS", payload="<script>alert(1)</script>",
                 finding_id="f001"):
    return {
        "vuln_class":  vuln_class,
        "severity":    severity,
        "url":         url,
        "summary":     summary,
        "payload":     payload,
        "id":          finding_id,
    }


# ---------------------------------------------------------------------------
# SARIFReporter tests
# ---------------------------------------------------------------------------

class TestSARIFReporter:

    def test_generate_returns_dict(self):
        reporter = SARIFReporter()
        session  = MockSession(findings=[make_finding()])
        sarif    = reporter.generate(session)
        assert isinstance(sarif, dict)

    def test_sarif_version_2_1_0(self):
        reporter = SARIFReporter()
        session  = MockSession(findings=[make_finding()])
        sarif    = reporter.generate(session)
        assert sarif["version"] == "2.1.0"

    def test_has_runs(self):
        reporter = SARIFReporter()
        session  = MockSession(findings=[make_finding()])
        sarif    = reporter.generate(session)
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_result_count_matches_findings(self):
        findings = [
            make_finding("xss",  "high",   finding_id="f1"),
            make_finding("sqli", "critical", finding_id="f2"),
            make_finding("ssrf", "medium",  finding_id="f3"),
        ]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        results  = sarif["runs"][0]["results"]
        assert len(results) == 3

    def test_rule_ids_deduplicated(self):
        """Two XSS findings should produce only one XSS rule."""
        findings = [
            make_finding("xss", finding_id="f1"),
            make_finding("xss", finding_id="f2"),
            make_finding("sqli", finding_id="f3"),
        ]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        rules    = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert rule_ids.count("xss") == 1
        assert "sqli" in rule_ids

    def test_critical_maps_to_error_level(self):
        findings = [make_finding("sqli", "critical", finding_id="f1")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        result   = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_medium_maps_to_warning_level(self):
        findings = [make_finding("ssrf", "medium", finding_id="f1")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        result   = sarif["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_low_maps_to_note_level(self):
        findings = [make_finding("cors", "low", finding_id="f1")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        result   = sarif["runs"][0]["results"][0]
        assert result["level"] == "note"

    def test_cvss_score_critical(self):
        findings = [make_finding("sqli", "critical", finding_id="f1")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["cvss_score"] == pytest.approx(9.5)

    def test_cvss_score_info(self):
        findings = [make_finding("info-leak", "info", finding_id="f1")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["cvss_score"] == pytest.approx(0.0)

    def test_physical_location_contains_uri(self):
        url      = "https://example.com/api/search?q=test"
        findings = [make_finding(url=url, finding_id="f1")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        loc      = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == url

    def test_empty_findings_produces_empty_results(self):
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=[]))
        assert sarif["runs"][0]["results"] == []

    def test_write_creates_file(self, tmp_path):
        findings = [make_finding()]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        out_path = str(tmp_path / "scan.sarif")
        written  = reporter.write(sarif, out_path)
        assert Path(written).exists()
        loaded   = json.loads(Path(written).read_text())
        assert loaded["version"] == "2.1.0"

    def test_chain_finding_has_related_locations(self):
        finding = {
            "vuln_class": "ssrf_internal",
            "severity":   "critical",
            "url":        "https://example.com/ssrf",
            "summary":    "Blind SSRF chain",
            "id":         "f002",
            "parent_finding_id": "f001",
        }
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=[finding]))
        result   = sarif["runs"][0]["results"][0]
        assert "relatedLocations" in result
        assert result["relatedLocations"][0]["message"]["text"].startswith("Chain parent")

    def test_valid_json_output(self, tmp_path):
        """Output file should be valid JSON."""
        findings = [make_finding("xss", "high", finding_id="f1"),
                    make_finding("sqli", "critical", finding_id="f2")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(MockSession(findings=findings))
        out_path = str(tmp_path / "test.sarif")
        reporter.write(sarif, out_path)
        text = Path(out_path).read_text()
        # Should not raise
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# avvp/libs/sarif_schema/sarif_builder.py tests (test_sarif.py extended)
# ---------------------------------------------------------------------------

class TestSARIFBuilder:

    def test_build_sarif_report_minimal(self):
        findings = [
            {"vuln_class": "XSS",  "severity": "high",     "uri": "https://example.com/",      "summary": "Reflected XSS",   "region": {}},
            {"vuln_class": "SQLI", "severity": "critical",  "uri": "https://example.com/login", "summary": "SQL Injection",   "region": {}},
        ]
        sarif = build_sarif_report(findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 2

    def test_validate_sarif_passes_on_valid(self):
        findings = [{"vuln_class": "XSS", "severity": "high", "uri": "https://x.com/", "summary": "XSS", "region": {}}]
        sarif    = build_sarif_report(findings)
        validate_sarif(sarif)  # should not raise

    def test_validate_sarif_fails_on_bad_version(self):
        sarif = {"version": "1.0", "runs": []}
        with pytest.raises(ValueError, match="version"):
            validate_sarif(sarif)

    def test_validate_sarif_fails_on_empty_runs(self):
        sarif = {"version": "2.1.0", "runs": []}
        with pytest.raises(ValueError, match="runs"):
            validate_sarif(sarif)

    def test_validate_sarif_fails_on_invalid_level(self):
        findings = [{"vuln_class": "XSS", "severity": "high", "uri": "https://x.com/", "summary": "x", "region": {}}]
        sarif    = build_sarif_report(findings)
        # Corrupt a result level
        sarif["runs"][0]["results"][0]["level"] = "INVALID"
        with pytest.raises(ValueError, match="level"):
            validate_sarif(sarif)

    def test_validate_sarif_fails_missing_rule_id(self):
        findings = [{"vuln_class": "XSS", "severity": "high", "uri": "https://x.com/", "summary": "x", "region": {}}]
        sarif    = build_sarif_report(findings)
        del sarif["runs"][0]["results"][0]["ruleId"]
        with pytest.raises(ValueError, match="ruleId"):
            validate_sarif(sarif)

    def test_severity_to_cvss_mapping(self):
        for sev, expected in [("critical", 9.5), ("high", 8.0), ("medium", 5.5), ("low", 3.0), ("info", 0.0)]:
            findings = [{"vuln_class": "test", "severity": sev, "uri": "https://x.com/", "summary": "s", "region": {}}]
            sarif    = build_sarif_report(findings)
            cvss     = sarif["runs"][0]["results"][0]["properties"]["cvss_score"]
            assert cvss == pytest.approx(expected), f"severity={sev}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
