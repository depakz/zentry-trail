from avvp.libs.sarif_schema.sarif_builder import build_sarif_report, validate_sarif


def test_sarif_minimal():
    findings = [
        {"vuln_class": "xss", "severity": "high", "uri": "https://example.com/", "summary": "Reflected XSS", "region": {}},
        {"vuln_class": "sqli", "severity": "high", "uri": "https://example.com/login", "summary": "SQL Injection", "region": {}},
    ]
    sarif = build_sarif_report(findings)
    validate_sarif(sarif)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    # Rule IDs should be CWE-based, not raw vuln_class
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "CWE-79" in rule_ids
    assert "CWE-89" in rule_ids
