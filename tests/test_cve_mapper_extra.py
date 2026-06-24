from zentry.chains.rules import CVEMapper, get_cve_info


def test_extra_cve_spec_and_mapping():
    mapper = CVEMapper()
    # New CVE should be present in the specs
    info = mapper.get_cve_verdict_data("CVE-2026-0001")
    assert info["cve_id"] == "CVE-2026-0001"
    assert info["severity"] in ("high", "critical", "unknown")

    # Map a finding that references the CVE in title
    findings = [{"title": "OpenSSL CVE-2026-0001 heartbeat issue"}]
    mapping = mapper.map_findings_to_cves(findings)
    assert "CVE-2026-0001" in mapping
    assert isinstance(mapping["CVE-2026-0001"], list)
