import pytest
from zentry.chains.rules import CHAIN_RULES
from zentry.chains.engine import ChainEngine

def test_chain_engine_csrf_account_takeover():
    engine = ChainEngine(CHAIN_RULES)

    findings = [
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=redir",
            "vulnerability": "open-redirect",
            "cvss": 6.5,
            "severity": "medium"
        },
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=csrf",
            "vulnerability": "csrf-missing-protections",
            "cvss": 7.2,
            "severity": "high"
        }
    ]

    chains = engine.evaluate(findings)
    assert len(chains) >= 2  # Matches chain-001 (CSRF + Open Redirect) and chain-002 (Open Redirect)
    chain = next(c for c in chains if c["chain_id"] == "chain-001")
    assert chain["name"] == "CSRF → Account Takeover"
    # Max CVSS (7.2) + boost (0.5 * (2 - 1)) = 7.7
    assert chain["cvss"] == 7.7
    assert len(chain["component_findings"]) == 2

def test_chain_engine_capping():
    engine = ChainEngine(CHAIN_RULES)

    findings = [
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=redir",
            "vulnerability": "open-redirect",
            "cvss": 9.8,
            "severity": "high"
        },
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=csrf",
            "vulnerability": "csrf-missing-protections",
            "cvss": 9.9,
            "severity": "critical"
        }
    ]

    chains = engine.evaluate(findings)
    chain = next(c for c in chains if c["chain_id"] == "chain-001")
    assert chain["cvss"] == 10.0  # capped
