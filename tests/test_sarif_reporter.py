"""
tests/test_sarif_reporter.py — SARIF 2.1.0 compliance tests

Tests for core/sarif_reporter.py and avvp/libs/sarif_schema/sarif_builder.py.
Validates CWE-mapped ruleIds, human-readable messages, per-finding CVSS,
confirmed_payload propagation, and structural SARIF 2.1.0 compliance.
"""

import json
import pytest
from pathlib import Path

from core.sarif_reporter import SARIFReporter, VALIDATOR_REGISTRY, _resolve_registry
from avvp.libs.sarif_schema.sarif_builder import build_sarif_report, validate_sarif


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockSession:
    """Minimal scan session for testing (legacy path)."""
    def __init__(self, findings=None, target="https://example.com", scan_id="scan-test-001"):
        self.findings = findings or []
        self.target   = target
        self.scan_id  = scan_id


def make_finding(vulnerability="xss", severity="high", target_url="https://example.com/search",
                 payload="<script>alert(1)</script>", cvss=8.0, finding_id="f001",
                 owasp="A03"):
    """Create a finding dict matching the report_payload format."""
    return {
        "vulnerability":  vulnerability,
        "severity":       severity,
        "target_url":     target_url,
        "payload":        payload,
        "cvss":           cvss,
        "score":          cvss,
        "id":             finding_id,
        "validator_name": f"{vulnerability}_validator",
        "owasp":          owasp,
    }


def make_legacy_finding(vuln_class="xss", severity="high", url="https://example.com/search",
                        summary="Reflected XSS", payload="<script>alert(1)</script>",
                        finding_id="f001"):
    """Create a finding dict for the sarif_builder.py (legacy vuln_class key)."""
    return {
        "vuln_class":  vuln_class,
        "severity":    severity,
        "url":         url,
        "summary":     summary,
        "payload":     payload,
        "id":          finding_id,
    }


# ---------------------------------------------------------------------------
# VALIDATOR_REGISTRY tests
# ---------------------------------------------------------------------------

class TestValidatorRegistry:
    """Validate the CWE mapping registry."""

    def test_required_entries_present(self):
        required = [
            "sql-injection", "reflected-xss", "open-redirect",
            "sensitive-file-exposure", "csrf-missing-protections",
            "server-version-disclosure", "xss",
        ]
        for key in required:
            assert key in VALIDATOR_REGISTRY, f"Missing registry entry: {key}"

    def test_registry_entries_have_required_keys(self):
        for slug, entry in VALIDATOR_REGISTRY.items():
            assert "ruleId" in entry, f"{slug}: missing ruleId"
            assert "name"   in entry, f"{slug}: missing name"
            assert "cwe"    in entry, f"{slug}: missing cwe"
            assert "owasp"  in entry, f"{slug}: missing owasp"

    def test_resolve_exact_match(self):
        reg = _resolve_registry("sql-injection")
        assert reg["ruleId"] == "CWE-89"
        assert reg["cwe"]    == "CWE-89"

    def test_resolve_substring_match(self):
        """'sql-injection-blind' should match 'sql-injection'."""
        reg = _resolve_registry("sql-injection-blind")
        assert reg["ruleId"] == "CWE-89"

    def test_resolve_unknown_produces_non_unknown_id(self):
        """Unknown vulns should get a synthetic ID, never 'unknown'."""
        reg = _resolve_registry("some-new-vuln-type")
        assert reg["ruleId"] != "unknown"
        assert reg["ruleId"] != ""

    def test_resolve_empty_string(self):
        reg = _resolve_registry("")
        assert reg["ruleId"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# SARIFReporter tests (new API: findings list)
# ---------------------------------------------------------------------------

class TestSARIFReporter:

    def test_generate_returns_dict(self):
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=[make_finding()])
        assert isinstance(sarif, dict)

    def test_sarif_version_2_1_0(self):
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=[make_finding()])
        assert sarif["version"] == "2.1.0"

    def test_has_runs(self):
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=[make_finding()])
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_result_count_matches_findings(self):
        findings = [
            make_finding("xss",  "high",   finding_id="f1"),
            make_finding("sqli", "critical", finding_id="f2", cvss=9.5),
            make_finding("ssrf", "medium",  finding_id="f3", cvss=5.5),
        ]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        results  = sarif["runs"][0]["results"]
        assert len(results) == 3

    def test_zero_results_with_unknown_rule_id(self):
        """ACCEPTANCE: Zero results with ruleId='unknown'."""
        findings = [
            make_finding("sql-injection", "critical", cvss=9.5, finding_id="f1"),
            make_finding("reflected-xss", "high",     cvss=8.0, finding_id="f2"),
            make_finding("open-redirect", "high",     cvss=9.6, finding_id="f3"),
            make_finding("csrf-missing-protections", "high", cvss=9.2, finding_id="f4"),
            make_finding("sensitive-file-exposure", "high", cvss=9.2, finding_id="f5"),
            make_finding("server-version-disclosure", "medium", cvss=5.5, finding_id="f6"),
        ]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        results  = sarif["runs"][0]["results"]
        unknown_results = [r for r in results if r["ruleId"] == "unknown"]
        assert len(unknown_results) == 0, f"Found {len(unknown_results)} results with ruleId='unknown'"

    def test_rules_count_equals_unique_vuln_types(self):
        """ACCEPTANCE: driver.rules[] length must equal unique vuln types."""
        findings = [
            make_finding("xss",  finding_id="f1"),
            make_finding("xss",  finding_id="f2"),  # duplicate type
            make_finding("sqli", finding_id="f3"),
            make_finding("open-redirect", finding_id="f4"),
        ]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        rules    = sarif["runs"][0]["tool"]["driver"]["rules"]
        # xss and sqli both map to CWE-79 / CWE-89, open-redirect to CWE-601
        rule_ids = {r["id"] for r in rules}
        assert len(rules) == len(rule_ids), "Rules should be deduplicated by ruleId"
        assert len(rules) == 3, f"Expected 3 unique rules, got {len(rules)}"

    def test_result_message_is_human_readable(self):
        """ACCEPTANCE: message.text must be human-readable, not 'unknown'."""
        findings = [make_finding("sql-injection", target_url="https://example.com/login")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        result   = sarif["runs"][0]["results"][0]
        msg      = result["message"]["text"]
        assert msg != "unknown"
        assert "Sql Injection" in msg or "SQL" in msg.upper()
        assert "https://example.com/login" in msg

    def test_confirmed_payload_non_empty_for_sqli(self):
        """ACCEPTANCE: confirmed_payload non-empty for SQLi."""
        findings = [make_finding("sql-injection", payload="' OR 1=1--")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["confirmed_payload"] == "' OR 1=1--"
        assert props["confirmed_payload"] != ""

    def test_confirmed_payload_non_empty_for_xss(self):
        """ACCEPTANCE: confirmed_payload non-empty for XSS."""
        findings = [make_finding("xss", payload="<script>alert(1)</script>")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["confirmed_payload"] == "<script>alert(1)</script>"

    def test_confirmed_payload_non_empty_for_open_redirect(self):
        """ACCEPTANCE: confirmed_payload non-empty for Open Redirect."""
        findings = [make_finding("open-redirect", payload="https://evil.com")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["confirmed_payload"] == "https://evil.com"

    def test_cvss_uses_actual_per_finding_score(self):
        """cvss_score must use actual per-finding CVSS, not hardcoded."""
        findings = [make_finding("xss", cvss=7.3, finding_id="f1")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["cvss_score"] == pytest.approx(7.3)

    def test_severity_propagated(self):
        findings = [make_finding("xss", severity="critical")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["severity"] == "critical"

    def test_owasp_propagated(self):
        findings = [make_finding("csrf-missing-protections", owasp="A01")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        props    = sarif["runs"][0]["results"][0]["properties"]
        assert props["owasp"] == "A01"

    def test_critical_maps_to_error_level(self):
        findings = [make_finding("sqli", "critical", cvss=9.5)]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        result   = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_medium_maps_to_warning_level(self):
        findings = [make_finding("ssrf", "medium", cvss=5.5)]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        result   = sarif["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_low_maps_to_note_level(self):
        findings = [make_finding("cors", "low", cvss=3.0)]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        result   = sarif["runs"][0]["results"][0]
        assert result["level"] == "note"

    def test_physical_location_contains_uri(self):
        url      = "https://example.com/api/search?q=test"
        findings = [make_finding(target_url=url)]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        loc      = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == url

    def test_empty_findings_produces_empty_results(self):
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=[])
        assert sarif["runs"][0]["results"] == []

    def test_write_creates_file(self, tmp_path):
        findings = [make_finding()]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        out_path = str(tmp_path / "scan.sarif")
        written  = reporter.write(sarif, out_path)
        assert Path(written).exists()
        loaded   = json.loads(Path(written).read_text())
        assert loaded["version"] == "2.1.0"

    def test_chain_finding_has_related_locations(self):
        finding = {
            "vulnerability":       "ssrf",
            "severity":            "critical",
            "target_url":          "https://example.com/ssrf",
            "payload":             "http://169.254.169.254",
            "cvss":                9.5,
            "score":               9.5,
            "id":                  "f002",
            "parent_finding_id":   "f001",
        }
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=[finding])
        result   = sarif["runs"][0]["results"][0]
        assert "relatedLocations" in result
        assert result["relatedLocations"][0]["message"]["text"].startswith("Chain parent")

    def test_valid_json_output(self, tmp_path):
        """Output file should be valid JSON."""
        findings = [
            make_finding("xss", "high", finding_id="f1"),
            make_finding("sqli", "critical", finding_id="f2", cvss=9.5),
        ]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        out_path = str(tmp_path / "test.sarif")
        reporter.write(sarif, out_path)
        text = Path(out_path).read_text()
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"

    def test_cwe_taxonomy_present(self):
        """SARIF output should include CWE taxonomy for CI/CD consumers."""
        findings = [
            make_finding("sql-injection", cvss=9.5),
            make_finding("xss", cvss=8.0),
        ]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        taxonomies = sarif["runs"][0].get("taxonomies", [])
        assert len(taxonomies) >= 1
        assert taxonomies[0]["name"] == "CWE"
        taxa = taxonomies[0]["taxa"]
        cwe_ids = {t["id"] for t in taxa}
        assert "CWE-89" in cwe_ids
        assert "CWE-79" in cwe_ids

    def test_rule_has_cwe_relationship(self):
        """Each rule should have a CWE relationship entry."""
        findings = [make_finding("sql-injection")]
        reporter = SARIFReporter()
        sarif    = reporter.generate(findings=findings)
        rule     = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "relationships" in rule
        rel = rule["relationships"][0]
        assert rel["target"]["id"] == "CWE-89"

    # ── Legacy session-based API still works ─────────────────────────────

    def test_legacy_session_api(self):
        """Legacy generate(session=...) path should still produce valid output."""
        from dataclasses import dataclass

        @dataclass
        class FakeFinding:
            id: str = "f1"
            title: str = "xss"
            severity: str = "high"
            endpoint: str = "https://example.com/"
            payload: str = "<img>"
            evidence: str = ""
            score: float = 8.0

        session = MockSession(findings=[FakeFinding()], target="https://example.com")
        reporter = SARIFReporter()
        sarif = reporter.generate(session=session)
        assert sarif["version"] == "2.1.0"
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] != "unknown"


# ---------------------------------------------------------------------------
# avvp/libs/sarif_schema/sarif_builder.py tests
# ---------------------------------------------------------------------------

class TestSARIFBuilder:

    def test_build_sarif_report_minimal(self):
        findings = [
            {"vuln_class": "xss",  "severity": "high",     "uri": "https://example.com/",      "summary": "Reflected XSS",   "region": {}},
            {"vuln_class": "sqli", "severity": "critical",  "uri": "https://example.com/login", "summary": "SQL Injection",   "region": {}},
        ]
        sarif = build_sarif_report(findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 2

    def test_validate_sarif_passes_on_valid(self):
        findings = [{"vuln_class": "xss", "severity": "high", "uri": "https://x.com/", "summary": "XSS", "region": {}}]
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
        findings = [{"vuln_class": "xss", "severity": "high", "uri": "https://x.com/", "summary": "x", "region": {}}]
        sarif    = build_sarif_report(findings)
        sarif["runs"][0]["results"][0]["level"] = "INVALID"
        with pytest.raises(ValueError, match="level"):
            validate_sarif(sarif)

    def test_validate_sarif_fails_missing_rule_id(self):
        findings = [{"vuln_class": "xss", "severity": "high", "uri": "https://x.com/", "summary": "x", "region": {}}]
        sarif    = build_sarif_report(findings)
        del sarif["runs"][0]["results"][0]["ruleId"]
        with pytest.raises(ValueError, match="ruleId"):
            validate_sarif(sarif)

    def test_builder_rule_ids_use_cwe(self):
        """Builder should produce CWE-based ruleIds, not raw vuln_class strings."""
        findings = [
            {"vuln_class": "xss",  "severity": "high", "uri": "https://x.com/", "summary": "XSS"},
            {"vuln_class": "sqli", "severity": "critical", "uri": "https://x.com/login", "summary": "SQLi"},
        ]
        sarif = build_sarif_report(findings)
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert "CWE-79" in rule_ids
        assert "CWE-89" in rule_ids

    def test_builder_result_rule_ids_match(self):
        """Each result ruleId should match a rule in driver.rules[]."""
        findings = [
            {"vuln_class": "xss",  "severity": "high", "uri": "https://x.com/", "summary": "XSS"},
            {"vuln_class": "sqli", "severity": "critical", "uri": "https://x.com/login", "summary": "SQLi"},
        ]
        sarif = build_sarif_report(findings)
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        for result in sarif["runs"][0]["results"]:
            assert result["ruleId"] in rule_ids, f"Result ruleId '{result['ruleId']}' not in rules"

    def test_builder_payload_propagated(self):
        findings = [{"vuln_class": "xss", "severity": "high", "uri": "https://x.com/", "summary": "XSS", "payload": "<img onerror=alert(1)>"}]
        sarif = build_sarif_report(findings)
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["confirmed_payload"] == "<img onerror=alert(1)>"

    def test_builder_cvss_from_finding(self):
        """Per-finding CVSS should be used, not hardcoded severity mapping."""
        findings = [{"vuln_class": "xss", "severity": "high", "uri": "https://x.com/", "summary": "XSS", "cvss": 7.3}]
        sarif = build_sarif_report(findings)
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["cvss_score"] == pytest.approx(7.3)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
