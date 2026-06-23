import pytest
from chains.rules import CHAIN_RULES
from chains.engine import ChainEngine

def test_chain_engine_xss_via_open_redirect():
    engine = ChainEngine(CHAIN_RULES)

    findings = [
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=redir",
            "vulnerability": "open-redirect",
            "cvss": 6.5,
            "severity": "medium"
        },
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=xss",
            "vulnerability": "reflected-xss",
            "cvss": 7.2,
            "severity": "high"
        }
    ]

    chains = engine.evaluate(findings)
    assert len(chains) == 1
    chain = chains[0]
    assert chain["chain_id"] == "chain-001"
    assert chain["name"] == "XSS via Open Redirect"
    # Max CVSS (7.2) + boost (0.3) = 7.5
    assert chain["cvss"] == 7.5
    assert len(chain["component_findings"]) == 2

def test_chain_engine_different_hosts_ignored():
    engine = ChainEngine(CHAIN_RULES)

    findings = [
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=redir",
            "vulnerability": "open-redirect",
            "cvss": 6.5,
            "severity": "medium"
        },
        {
            "target_url": "http://other-domain.com/index.jsp?content=xss",
            "vulnerability": "reflected-xss",
            "cvss": 7.2,
            "severity": "high"
        }
    ]

    chains = engine.evaluate(findings)
    assert len(chains) == 0

def test_chain_engine_cvss_capping():
    engine = ChainEngine(CHAIN_RULES)

    findings = [
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=redir",
            "vulnerability": "open-redirect",
            "cvss": 9.8,
            "severity": "high"
        },
        {
            "target_url": "http://altoro.testfire.net/index.jsp?content=xss",
            "vulnerability": "reflected-xss",
            "cvss": 9.9,
            "severity": "critical"
        }
    ]

    chains = engine.evaluate(findings)
    assert len(chains) == 1
    assert chains[0]["cvss"] == 10.0  # capped
