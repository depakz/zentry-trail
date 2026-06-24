"""
Unit tests for core.dedup — finding deduplication pipeline.

Validates:
  - Duplicate (target_url, vulnerability) pairs are collapsed to one entry
  - The entry with the higher CVSS is kept
  - max(cvss) and max(score) are preserved in the merged result
  - SHA-256 keying works correctly
  - Edge cases: empty list, single finding, no duplicates
  - Finding dataclass dedup via dedup_finding_objects
"""

import hashlib
from dataclasses import dataclass, field

from zentry.reporting.dedup import dedup_findings, dedup_finding_objects, _dedup_key


# ── Tests for dedup_findings (dict-based) ────────────────────────────────────

class TestDedupFindings:
    """Tests for the dict-based dedup_findings function."""

    def test_duplicate_url_keeps_higher_cvss(self):
        """
        Given two findings for the same (target_url, vulnerability) pair
        with CVSS 9.2 and 8.8, assert output length == 1 and cvss == 9.2.
        """
        findings = [
            {
                "target_url": "/admin/clients.xls",
                "vulnerability": "sensitive-data-exposure",
                "cvss": 9.2,
                "score": 9.2,
                "severity": "critical",
                "validator_name": "data_exposure_validator",
            },
            {
                "target_url": "/admin/clients.xls",
                "vulnerability": "sensitive-data-exposure",
                "cvss": 8.8,
                "score": 8.8,
                "severity": "high",
                "validator_name": "data_exposure_validator",
            },
        ]
        result = dedup_findings(findings)

        assert len(result) == 1, f"Expected 1 finding, got {len(result)}"
        assert result[0]["cvss"] == 9.2, f"Expected CVSS 9.2, got {result[0]['cvss']}"
        assert result[0]["score"] == 9.2, f"Expected score 9.2, got {result[0]['score']}"

    def test_max_score_merged_when_lower_cvss_has_higher_score(self):
        """max(score) should be preserved even when the lower-CVSS entry has a higher score."""
        findings = [
            {
                "target_url": "/api/v1/users",
                "vulnerability": "idor",
                "cvss": 7.5,
                "score": 9.0,
            },
            {
                "target_url": "/api/v1/users",
                "vulnerability": "idor",
                "cvss": 8.0,
                "score": 7.0,
            },
        ]
        result = dedup_findings(findings)

        assert len(result) == 1
        assert result[0]["cvss"] == 8.0, "Should keep max CVSS"
        assert result[0]["score"] == 9.0, "Should merge max score"

    def test_no_duplicates_preserves_all(self):
        """Distinct (url, vuln_type) pairs should all be preserved."""
        findings = [
            {"target_url": "/login", "vulnerability": "xss", "cvss": 6.0, "score": 6.0},
            {"target_url": "/login", "vulnerability": "sqli", "cvss": 8.0, "score": 8.0},
            {"target_url": "/admin", "vulnerability": "xss", "cvss": 7.0, "score": 7.0},
        ]
        result = dedup_findings(findings)
        assert len(result) == 3

    def test_empty_input(self):
        """Empty input returns empty output."""
        assert dedup_findings([]) == []

    def test_single_finding(self):
        """Single finding passes through unchanged."""
        findings = [
            {"target_url": "/test", "vulnerability": "csrf", "cvss": 5.0, "score": 5.0}
        ]
        result = dedup_findings(findings)
        assert len(result) == 1
        assert result[0]["cvss"] == 5.0

    def test_eight_to_seven_reduction(self):
        """
        Simulate the altoro test run: 8 findings with one duplicate pair,
        expect reduction to 7.
        """
        findings = [
            {"target_url": "/admin/clients.xls", "vulnerability": "sensitive-data-exposure", "cvss": 9.2, "score": 9.2},
            {"target_url": "/admin/clients.xls", "vulnerability": "sensitive-data-exposure", "cvss": 8.8, "score": 8.8},
            {"target_url": "/index.jsp", "vulnerability": "open-redirect", "cvss": 9.6, "score": 9.6},
            {"target_url": "/bank/transfer", "vulnerability": "csrf", "cvss": 9.2, "score": 9.2},
            {"target_url": "/login", "vulnerability": "xss", "cvss": 6.5, "score": 6.5},
            {"target_url": "/api/users", "vulnerability": "idor", "cvss": 7.0, "score": 7.0},
            {"target_url": "/debug", "vulnerability": "ssrf", "cvss": 8.0, "score": 8.0},
            {"target_url": "/config", "vulnerability": "misconfiguration", "cvss": 5.5, "score": 5.5},
        ]
        result = dedup_findings(findings)
        assert len(result) == 7, f"Expected 7, got {len(result)}"
        # /admin/clients.xls should appear exactly once with CVSS = 9.2
        admin_findings = [f for f in result if f["target_url"] == "/admin/clients.xls"]
        assert len(admin_findings) == 1
        assert admin_findings[0]["cvss"] == 9.2

    def test_sha256_key_correctness(self):
        """Verify the SHA-256 key is computed correctly."""
        finding = {"target_url": "/admin/clients.xls", "vulnerability": "sensitive-data-exposure"}
        expected = hashlib.sha256(b"/admin/clients.xlssensitive-data-exposure").hexdigest()
        assert _dedup_key(finding) == expected

    def test_preserves_insertion_order(self):
        """Results should maintain the order of first occurrence."""
        findings = [
            {"target_url": "/a", "vulnerability": "xss", "cvss": 5.0, "score": 5.0},
            {"target_url": "/b", "vulnerability": "sqli", "cvss": 7.0, "score": 7.0},
            {"target_url": "/c", "vulnerability": "csrf", "cvss": 6.0, "score": 6.0},
        ]
        result = dedup_findings(findings)
        assert [f["target_url"] for f in result] == ["/a", "/b", "/c"]

    def test_skips_non_dict_items(self):
        """Non-dict items in the list should be silently skipped."""
        findings = [
            {"target_url": "/test", "vulnerability": "xss", "cvss": 5.0, "score": 5.0},
            None,
            "invalid",
            42,
        ]
        result = dedup_findings(findings)
        assert len(result) == 1


# ── Tests for dedup_finding_objects (dataclass-based) ────────────────────────

@dataclass
class MockFinding:
    """Simplified Finding-like dataclass for testing."""
    id: str = ""
    title: str = ""
    severity: str = "medium"
    endpoint: str = ""
    score: float = 0.0


class TestDedupFindingObjects:
    """Tests for the Finding-object-based dedup_finding_objects function."""

    def test_duplicate_finding_objects(self):
        """Duplicate Finding objects should be collapsed to one."""
        f1 = MockFinding(id="a", title="xss", endpoint="/login", score=8.0)
        f2 = MockFinding(id="b", title="xss", endpoint="/login", score=6.0)
        result = dedup_finding_objects([f1, f2])
        assert len(result) == 1
        assert result[0].score == 8.0

    def test_distinct_finding_objects_preserved(self):
        """Distinct Finding objects should all be preserved."""
        f1 = MockFinding(id="a", title="xss", endpoint="/login", score=8.0)
        f2 = MockFinding(id="b", title="sqli", endpoint="/login", score=7.0)
        result = dedup_finding_objects([f1, f2])
        assert len(result) == 2

    def test_empty_finding_objects(self):
        """Empty input returns empty output."""
        assert dedup_finding_objects([]) == []
