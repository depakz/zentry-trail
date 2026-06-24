from zentry.chains.rules import extract_cve_ids, CVEMapper, get_cve_info


def test_extract_cve_ids_direct_and_title():
    finding = {"cve": "CVE-2025-46817", "title": "Some redis issue CVE-2025-46817"}
    ids = extract_cve_ids(finding)
    assert "CVE-2025-46817" in ids

    finding2 = {"title": "No CVE here"}
    assert extract_cve_ids(finding2) == []


def test_cve_mapper_maps_and_gets_info():
    mapper = CVEMapper()
    findings = [{"cve": ["CVE-2025-46817"]}, {"title": "Redis CVE-2025-46817"}]
    mapping = mapper.map_findings_to_cves(findings)
    assert "CVE-2025-46817" in mapping
    assert isinstance(mapping["CVE-2025-46817"], list)

    info = mapper.get_cve_verdict_data("CVE-2025-46817")
    assert info["cve_id"] == "CVE-2025-46817"

    unknown = mapper.get_cve_verdict_data("CVE-XXXX-0000")
    assert unknown["severity"] == "unknown"

    spec = get_cve_info("CVE-2025-46817")
    assert spec is not None
