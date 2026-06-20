"""Tests for Cryptographic Evidence Store and SARIF Reporter (Session 8)."""

import json
import pytest
from pathlib import Path

from core.evidence_store import EvidenceStore
from core.sarif_reporter import SARIFReporter

def test_key_generation():
    store = EvidenceStore()
    assert store.private_key is not None
    assert store.public_key is not None

def test_store_and_verify(tmp_path):
    store = EvidenceStore(output_dir=str(tmp_path))
    finding_id = "f-123"
    req = {"method": "GET", "url": "http://test"}
    res = {"status": 200}
    
    req_ref, res_ref = store.store_http_pair(finding_id, req, res)
    assert req_ref.signature != ""
    assert res_ref.signature != ""
    
    bundle = store.generate_bundle(finding_id)
    assert len(bundle["artifacts"]) == 2
    assert "merkle_root" in bundle
    
    # Verify pristine bundle
    assert store.verify_bundle(finding_id) is True
    
    # Tamper payload
    artifact_file = Path(req_ref.s3_key)
    artifact_file.write_bytes(b"tampered content")
    
    # Verify tampered bundle immediately flags as false
    assert store.verify_bundle(finding_id) is False

def test_merkle_root_tamper(tmp_path):
    store = EvidenceStore(output_dir=str(tmp_path))
    finding_id = "f-999"
    store.store_http_pair(finding_id, {"q": 1}, {"r": 2})
    
    bundle = store.generate_bundle(finding_id)
    assert store.verify_bundle(finding_id) is True
    
    # Tamper the merkle root directly inside the bundle structure
    bundle_path = Path(store.output_dir) / finding_id / "bundle.json"
    data = json.loads(bundle_path.read_text())
    data["merkle_root"] = "deadbeef" * 8
    bundle_path.write_text(json.dumps(data))
    
    # Verify that Merkle tree compromise is detected
    assert store.verify_bundle(finding_id) is False

def test_sarif_reporter_schema():
    class MockFinding:
        def __init__(self):
            self.id = "f-123"
            self.vuln_class = "xss"
            self.severity = "high"
            self.url = "http://test"
            self.summary = "Cross-site scripting"
            self.payload = "<script>1</script>"
            self.parent_finding_id = None
    
    class MockSession:
        def __init__(self):
            self.findings = [MockFinding()]
            self.target = "http://test"
            self.scan_id = "scan-123"
            
    reporter = SARIFReporter()
    sarif = reporter.generate(MockSession())
    
    schema = {
        "type": "object",
        "properties": {
            "version": {"type": "string", "enum": ["2.1.0"]},
            "runs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "object"},
                        "results": {"type": "array"}
                    },
                    "required": ["tool", "results"]
                }
            }
        },
        "required": ["version", "runs"]
    }
    
    try:
        import jsonschema
        jsonschema.validate(instance=sarif, schema=schema)
    except ImportError:
        assert sarif.get("version") == "2.1.0"
        assert isinstance(sarif.get("runs"), list)
        assert "tool" in sarif["runs"][0]
        assert "results" in sarif["runs"][0]
    
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "xss"
    assert result["level"] == "error"
    assert result["properties"]["cvss_score"] == 8.0