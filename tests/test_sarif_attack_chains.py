import pytest
from core.sarif_reporter import SARIFReporter

def test_sarif_reporter_with_attack_chains():
    reporter = SARIFReporter()

    findings = [
        {
            "vulnerability": "open-redirect",
            "severity": "medium",
            "target_url": "http://altoro.testfire.net/index.jsp?content=redir",
            "cvss": 6.5
        },
        {
            "vulnerability": "reflected-xss",
            "severity": "high",
            "target_url": "http://altoro.testfire.net/index.jsp?content=xss",
            "cvss": 7.2
        }
    ]

    attack_chains = [
        {
            "chain_id": "chain-001",
            "name": "XSS via Open Redirect",
            "description": "Attacker abuses Open Redirect on same host to bypass CSP and deliver XSS payload to victim",
            "severity": "critical",
            "owasp": "A03",
            "component_findings": findings,
            "cvss": 7.5
        }
    ]

    sarif = reporter.generate(
        findings=findings,
        target="http://altoro.testfire.net",
        attack_chains=attack_chains
    )

    # Check that driver.notifications is populated
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert "notifications" in driver
    notifications = driver["notifications"]
    assert len(notifications) == 1

    notif = notifications[0]
    assert notif["id"] == "chain-001"
    assert notif["level"] == "error"
    assert "XSS via Open Redirect" in notif["message"]["text"]
    assert notif["properties"]["cvss"] == 7.5
    assert notif["properties"]["owasp"] == "A03"
    assert "open-redirect" in notif["properties"]["component_findings"]
    assert "reflected-xss" in notif["properties"]["component_findings"]
