"""Session 10: Integration and end-to-end test."""

import asyncio
import time
import pytest
from unittest.mock import MagicMock, patch
from core.genetic_engine import PayloadGene, DifferentialAnalyzer
from core.traffic_normalization import NormalizedHTTPClient
from core.mcts_planner import AttackGraphNode, DeadlineAwareMCTS, SimpleGNN
from core.chain_synthesis import extract_artifacts_from_response, TypeCompatibilityResolver
from core.evidence_store import EvidenceStore
from core.self_training import OutcomeDB, PostScanFineTuner


class TestIntegration:
    """Integration tests for all components."""

    def test_payload_gene_rendering(self):
        """Payload genes should render correctly with all encodings."""
        gene = PayloadGene(
            vuln_class="SQLI",
            core_payload="1' OR '1'='1",
            encoding_layer="url",
            delimiter="'",
        )
        rendered = gene.render()
        assert "1" in rendered
        assert "%" in rendered  # URL encoded
        assert "'" in rendered

    def test_differential_analyzer(self):
        """DifferentialAnalyzer should compute fitness scores."""
        baseline = MagicMock()
        baseline.elapsed.total_seconds.return_value = 0.1
        baseline.status_code = 200
        baseline.text = "normal response"
        baseline.headers = {"Content-Type": "text/html"}

        probe = MagicMock()
        probe.elapsed.total_seconds.return_value = 5.0  # Timeout
        probe.status_code = 500
        probe.text = "error"
        probe.headers = {"Content-Type": "text/html", "X-Debug": "true"}

        delta = DifferentialAnalyzer.analyze(baseline, probe, oob_triggered=False)
        assert delta.fitness_score > 0.0
        assert delta.time_delta_ms > 4000
        assert "200→500" in delta.status_code_change
        assert "X-Debug" in delta.new_headers

    def test_traffic_normalization_client(self):
        """NormalizedHTTPClient should provide correct headers."""
        client = NormalizedHTTPClient(profile_name="chrome124")
        headers = client.get_headers()

        assert "User-Agent" in headers
        assert "Chrome" in headers["User-Agent"]
        assert "Accept" in headers
        assert "Accept-Language" in headers

    def test_attack_graph_node_featurization(self):
        """AttackGraphNode should featurize to 32-dim vector."""
        node = AttackGraphNode(
            node_id="node1",
            url="http://example.com",
            priority_score=0.8,
            confirmed_findings=["finding1"],
        )
        features = node.featurize()
        assert features.shape == (32,)

    def test_mcts_planner_ordering(self):
        """MCTS should order nodes by policy score."""
        gnn = SimpleGNN()
        planner = DeadlineAwareMCTS(gnn, time.time() + 60)

        nodes = [
            AttackGraphNode("n1", "url1", 0.5, []),
            AttackGraphNode("n2", "url2", 0.9, []),
            AttackGraphNode("n3", "url3", 0.3, []),
        ]

        ordered = planner.plan(nodes)
        assert len(ordered) == 3
        # n2 should have highest priority (0.9)
        assert ordered[0].priority_score >= 0.5

    def test_artifact_extraction(self):
        """Artifact extraction should find credentials and IPs."""
        response = "AWS Key: AKIA1234567890ABCDEF, IP: 10.0.0.1, JWT: eyJhbGc..."
        artifacts = extract_artifacts_from_response(response)

        assert any(a["type"] == "CREDENTIAL:AWS_KEY" for a in artifacts)
        assert any(a["type"] == "ENDPOINT:INTERNAL_IP" for a in artifacts)
        assert any(a["type"] == "CREDENTIAL:JWT_SIGNED" for a in artifacts)

    def test_type_resolver(self):
        """Type resolver should match artifacts to attacks."""
        resolver = TypeCompatibilityResolver()
        artifacts = [
            {"type": "CREDENTIAL:AWS_KEY", "value": "key"},
            {"type": "ENDPOINT:INTERNAL_IP", "value": "10.0.0.1"},
        ]

        candidates = resolver.resolve(artifacts)
        assert len(candidates) > 0
        assert any(c.attack_type == "cloud_credential_abuse" for c in candidates)
        assert any(c.attack_type == "ssrf_internal" for c in candidates)

    def test_evidence_store(self):
        """EvidenceStore should store artifacts."""
        store = EvidenceStore()
        ref = store.store_artifact("finding1", "http_request", b"test data")

        assert ref is not None
        assert ref.artifact_type == "http_request"
        assert ref.content_hash.startswith("916f002")  # sha256(b"test data")

    def test_outcome_db(self):
        """OutcomeDB should record scan outcomes."""
        db = OutcomeDB(db_path=":memory:")

        db.record_scan("scan1", "example.com", 1000)
        db.record_finding("find1", "scan1", "xss", "http://example.com", 0.9)
        db.record_node_decision("scan1", "node1", 0.8, 1, 1)

        data = db.get_training_data("scan1")
        assert len(data) == 1
        assert data[0]["node_id"] == "node1"
        assert data[0]["led_to_finding"] == 1

    def test_fine_tuner(self):
        """PostScanFineTuner should update GNN weights."""
        gnn = SimpleGNN()
        tuner = PostScanFineTuner()
        db = OutcomeDB(db_path=":memory:")

        db.record_scan("scan1", "example.com", 1000)
        db.record_node_decision("scan1", "n1", 0.5, 1, 1)
        db.record_node_decision("scan1", "n2", 0.8, 2, 0)

        original_w2 = gnn.W2.copy()
        gnn = tuner.fine_tune(gnn, "scan1", db)

        # Weights should have changed
        assert not (gnn.W2 == original_w2).all()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
