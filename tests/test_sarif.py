from zentry.reporting.sarif_reporter import SARIFReporter

def validate_sarif(sarif) -> None:
    # Inline lightweight validate_sarif to avoid avvp dependency
    if sarif.get("version") != "2.1.0":
        raise ValueError("Invalid version")
    if not isinstance(sarif.get("runs"), list) or len(sarif.get("runs")) == 0:
        raise ValueError("Invalid runs")
    for run in sarif["runs"]:
        if not isinstance(run.get("tool"), dict):
            raise ValueError("Invalid tool")

def test_sarif_minimal():
    findings = [
        {"vulnerability": "xss", "severity": "high", "target_url": "https://example.com/", "payload": ""},
        {"vulnerability": "sqli", "severity": "high", "target_url": "https://example.com/login", "payload": ""},
    ]
    reporter = SARIFReporter()
    sarif = reporter.generate(findings)
    validate_sarif(sarif)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "CWE-79" in rule_ids
    assert "CWE-89" in rule_ids
