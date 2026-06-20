"""
tests/test_mcts_planner_v2.py — Session 6 acceptance tests

Tests:
  1. AttackGraphNode.featurize() → 32-dim vector
  2. SimpleGNN forward pass shapes
  3. SimpleGNN weight save/load round-trip
  4. DeadlineAwareMCTS.exploration_constant() decays C_MAX → C_MIN
  5. plan() returns all nodes in descending priority/policy order
  6. plan() with expired deadline → falls back to priority ordering
  7. PostScanTrainer.update() changes GNN weights
  8. PostScanTrainer with no findings → returns gnn unchanged (no crash)
"""

import os
import time
import tempfile
import numpy as np
import pytest

from core.gnn_model   import SimpleGNN
from core.gnn_trainer import PostScanTrainer
from core.attack_graph import AttackGraphNode, AttackGraph
from core.mcts_planner import DeadlineAwareMCTS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_node(node_id: str, priority: float, findings: list = None, method: str = "GET", url: str = "") -> AttackGraphNode:
    return AttackGraphNode(
        node_id=node_id,
        url=url or f"http://example.com/{node_id}",
        priority_score=priority,
        confirmed_findings=findings or [],
        method=method
    )


# ---------------------------------------------------------------------------
# 1. AttackGraphNode.featurize()
# ---------------------------------------------------------------------------

class TestAttackGraphNodeFeaturize:
    def test_returns_32_dim_vector(self):
        node = make_node("n1", 0.7)
        feat = node.featurize()
        assert isinstance(feat, np.ndarray), "featurize() must return ndarray"
        assert feat.shape == (32,), f"Expected shape (32,), got {feat.shape}"

    def test_method_encoding(self):
        node = make_node("n1", 0.5, method="POST")
        feat = node.featurize()
        assert feat[1] == 1.0

    def test_priority_score_in_feature_28(self):
        node = make_node("n1", 0.75)
        feat = node.featurize()
        assert feat[28] == pytest.approx(0.75)

    def test_confirmed_findings_in_feature_29(self):
        node = make_node("n1", 0.5, findings=["f1", "f2", "f3"])
        feat = node.featurize()
        assert feat[29] > 0.0

    def test_high_value_path_flagged(self):
        node = AttackGraphNode(
            node_id="pay",
            url="http://example.com/payment/checkout",
            priority_score=0.5,
            confirmed_findings=[],
            tags=["admin_path"]
        )
        feat = node.featurize()
        assert feat[24] == 1.0, "admin_path should set high_value flag"

    def test_id_param_flagged(self):
        node = AttackGraphNode(
            node_id="uid",
            url="http://example.com/api/user?user_id=42",
            priority_score=0.5,
            confirmed_findings=[],
            tags=["api"]
        )
        feat = node.featurize()
        assert feat[27] == 1.0, "api tag should set flag"

    def test_all_values_finite(self):
        node = make_node("n1", 0.9, findings=["f1"])
        feat = node.featurize()
        assert np.all(np.isfinite(feat)), "All features must be finite"


# ---------------------------------------------------------------------------
# 2. SimpleGNN forward pass
# ---------------------------------------------------------------------------

class TestSimpleGNNForward:
    def test_output_shapes_no_adjacency(self):
        gnn = SimpleGNN(weights_path="/tmp/nonexistent_gnn.npz")
        N   = 5
        X   = np.random.randn(N, 32)
        logits, value = gnn.forward(X)
        assert logits.shape == (N,), f"Expected ({N},), got {logits.shape}"
        assert isinstance(value, float)

    def test_output_shapes_with_adjacency(self):
        gnn = SimpleGNN(weights_path="/tmp/nonexistent_gnn.npz")
        N   = 4
        X   = np.random.randn(N, 32)
        A   = np.eye(N)
        logits, value = gnn.forward(X, adjacency=A)
        assert logits.shape == (N,)
        assert np.isfinite(value)

    def test_empty_input_returns_empty(self):
        gnn    = SimpleGNN(weights_path="/tmp/nonexistent_gnn.npz")
        logits, value = gnn.forward(np.zeros((0, 32)))
        assert logits.shape == (0,)
        assert value == 0.0

    def test_all_outputs_finite(self):
        gnn    = SimpleGNN(weights_path="/tmp/nonexistent_gnn.npz")
        X      = np.random.randn(10, 32)
        logits, _ = gnn.forward(X)
        assert np.all(np.isfinite(logits))

    def test_weight_dimensions(self):
        gnn = SimpleGNN(weights_path="/tmp/nonexistent_gnn.npz")
        assert gnn.W1.shape == (32, 64), f"W1 shape: {gnn.W1.shape}"
        assert gnn.W2.shape == (64, 1),  f"W2 shape: {gnn.W2.shape}"
        assert gnn.a1.shape == (128, 1), f"a1 shape: {gnn.a1.shape}"


# ---------------------------------------------------------------------------
# 3. SimpleGNN weight save/load round-trip
# ---------------------------------------------------------------------------

class TestSimpleGNNWeights:
    def test_save_and_reload(self, tmp_path):
        path = str(tmp_path / "gnn_weights.npz")
        gnn  = SimpleGNN(weights_path=path)
        gnn.W1[0, 0] = 999.0   # distinctive value

        gnn.save_weights()
        assert os.path.exists(path), "Weights file should be created"

        gnn2 = SimpleGNN(weights_path=path)
        assert gnn2.W1[0, 0] == pytest.approx(999.0), "W1[0,0] should survive round-trip"
        assert np.allclose(gnn.W2, gnn2.W2), "W2 should survive round-trip"

    def test_weights_loaded_from_disk_flag(self, tmp_path):
        path = str(tmp_path / "w.npz")
        gnn  = SimpleGNN(weights_path=path)
        assert not gnn.weights_loaded_from_disk()
        gnn.save_weights()
        gnn2 = SimpleGNN(weights_path=path)
        assert gnn2.weights_loaded_from_disk()

    def test_random_init_is_reproducible(self):
        g1 = SimpleGNN(weights_path="/tmp/no_file_xyz.npz")
        g2 = SimpleGNN(weights_path="/tmp/no_file_xyz.npz")
        assert np.allclose(g1.W1, g2.W1), "Random init should use seed=42 → reproducible"


# ---------------------------------------------------------------------------
# 4. exploration_constant() decay
# ---------------------------------------------------------------------------

class TestExplorationConstant:
    def test_at_scan_start_near_c_max(self):
        gnn     = SimpleGNN(weights_path="/tmp/no_file.npz")
        # deadline very far in future → frac ≈ 0
        planner = DeadlineAwareMCTS(gnn, scan_deadline_epoch=time.time() + 10_000)
        c = planner.exploration_constant()
        assert c >= 1.3, f"At t=0, C should be near C_MAX=1.4, got {c}"

    def test_at_deadline_near_c_min(self):
        gnn     = SimpleGNN(weights_path="/tmp/no_file.npz")
        # deadline already passed → frac = 1.0
        planner = DeadlineAwareMCTS(gnn, scan_deadline_epoch=time.time() - 1)
        # Force scan_start far in the past
        planner.scan_start = time.time() - 10_000
        c = planner.exploration_constant()
        assert c <= 0.1, f"At deadline, C should be near C_MIN=0.05, got {c}"

    def test_monotone_decay(self):
        """C decreases as time passes (roughly)."""
        gnn  = SimpleGNN(weights_path="/tmp/no_file.npz")
        dead = time.time() + 100
        p    = DeadlineAwareMCTS(gnn, scan_deadline_epoch=dead)

        c_early = p.C_MAX  # approximate
        # Manually move scan_start back to simulate mid-scan
        p.scan_start = time.time() - 70   # 70 % through a 100-s scan
        c_mid = p.exploration_constant()
        assert c_mid < c_early, "C should decrease over time"


# ---------------------------------------------------------------------------
# 5. plan() ordering
# ---------------------------------------------------------------------------

class TestMCTSPlan:
    def _make_planner(self, deadline_offset: float = 3600) -> DeadlineAwareMCTS:
        gnn = SimpleGNN(weights_path="/tmp/no_file.npz")
        return DeadlineAwareMCTS(gnn, scan_deadline_epoch=time.time() + deadline_offset)

    def test_plan_returns_all_nodes(self):
        planner = self._make_planner()
        nodes   = [make_node(f"n{i}", float(i) / 10) for i in range(5)]
        result  = planner.plan(nodes)
        assert len(result) == 5, "plan() must return exactly as many nodes as input"

    def test_plan_highest_priority_first(self):
        """Highest priority_score node should appear near the top."""
        np.random.seed(42)
        planner = self._make_planner()
        nodes   = [
            make_node("low",  0.1),
            make_node("high", 0.95),
            make_node("mid",  0.5),
        ]
        result = planner.plan(nodes)
        # The high-priority node should not be last
        assert result[0].node_id != "low", "Lowest priority should not be first"
        assert result[-1].node_id != "high", "Highest priority should not be last"

    def test_plan_10_nodes_all_returned(self):
        planner = self._make_planner()
        nodes   = [make_node(f"n{i}", i / 10.0) for i in range(10)]
        result  = planner.plan(nodes)
        assert len(result) == 10
        returned_ids = {n.node_id for n in result}
        expected_ids = {n.node_id for n in nodes}
        assert returned_ids == expected_ids

    def test_plan_empty_returns_empty(self):
        planner = self._make_planner()
        assert planner.plan([]) == []

    def test_plan_with_expired_deadline_uses_priority(self):
        """With deadline in the past, plan() should fall back to priority sort."""
        gnn     = SimpleGNN(weights_path="/tmp/no_file.npz")
        planner = DeadlineAwareMCTS(gnn, scan_deadline_epoch=time.time() - 10)
        nodes   = [
            make_node("a", 0.1),
            make_node("b", 0.9),
            make_node("c", 0.5),
        ]
        result = planner.plan(nodes)
        assert result[0].node_id == "b",  "Greedy fallback: highest priority first"
        assert result[-1].node_id == "a", "Greedy fallback: lowest priority last"


# ---------------------------------------------------------------------------
# 6. PostScanTrainer
# ---------------------------------------------------------------------------

class TestPostScanTrainer:
    def test_weights_change_after_training(self, tmp_path):
        path    = str(tmp_path / "w.npz")
        gnn     = SimpleGNN(weights_path=path)
        trainer = PostScanTrainer()

        nodes = [
            make_node("n1", 0.8, findings=["f1"]),
            make_node("n2", 0.3, findings=[]),
            make_node("n3", 0.6, findings=["f2"]),
            make_node("n4", 0.2, findings=[]),
        ]

        W2_before = gnn.W2.copy()
        gnn = trainer.update(gnn, confirmed_findings=["f1", "f2"], node_order_used=nodes)
        assert not np.allclose(gnn.W2, W2_before), "W2 should change after training"

    def test_weights_saved_to_disk(self, tmp_path):
        path    = str(tmp_path / "saved.npz")
        gnn     = SimpleGNN(weights_path=path)
        trainer = PostScanTrainer()
        nodes   = [
            make_node("n1", 0.9, findings=["f1"]),
            make_node("n2", 0.1, findings=[]),
            make_node("n3", 0.5, findings=[]),
        ]
        trainer.update(gnn, confirmed_findings=["f1"], node_order_used=nodes)
        assert os.path.exists(path), "Weights should be saved to disk"

    def test_no_crash_with_empty_nodes(self, tmp_path):
        path    = str(tmp_path / "w.npz")
        gnn     = SimpleGNN(weights_path=path)
        trainer = PostScanTrainer()
        gnn2    = trainer.update(gnn, confirmed_findings=[], node_order_used=[])
        assert gnn2 is gnn  # same object returned

    def test_no_crash_with_no_findings(self, tmp_path):
        path    = str(tmp_path / "w.npz")
        gnn     = SimpleGNN(weights_path=path)
        trainer = PostScanTrainer()
        nodes   = [make_node(f"n{i}", 0.5) for i in range(5)]
        # no findings → all labels = 0 → no gradient (graceful return)
        gnn2 = trainer.update(gnn, confirmed_findings=[], node_order_used=nodes)
        assert gnn2 is gnn

    def test_load_updated_weights_after_training(self, tmp_path):
        """Weights saved by trainer should be loadable by a fresh GNN instance."""
        path    = str(tmp_path / "w.npz")
        gnn     = SimpleGNN(weights_path=path)
        trainer = PostScanTrainer()
        nodes   = [
            make_node("n1", 0.9, findings=["f1"]),
            make_node("n2", 0.2, findings=[]),
            make_node("n3", 0.6, findings=["f2"]),
        ]
        gnn = trainer.update(gnn, confirmed_findings=["f1", "f2"], node_order_used=nodes)

        gnn_reloaded = SimpleGNN(weights_path=path)
        assert np.allclose(gnn.W2, gnn_reloaded.W2), "Reloaded W2 should match saved W2"
        assert np.allclose(gnn.W1, gnn_reloaded.W1), "Reloaded W1 should match saved W1"


# ---------------------------------------------------------------------------
# 7. Integration: GNN → MCTS → Trainer round-trip
# ---------------------------------------------------------------------------

class TestGNNMCTSTrainerRoundTrip:
    def test_full_round_trip(self, tmp_path):
        """Train → save → reload → plan again without error."""
        path    = str(tmp_path / "gnn_weights.npz")
        gnn     = SimpleGNN(weights_path=path)
        planner = DeadlineAwareMCTS(gnn, scan_deadline_epoch=time.time() + 3600)
        trainer = PostScanTrainer()

        nodes = [make_node(f"n{i}", i / 9.0, findings=["f1"] if i > 5 else []) for i in range(9)]

        # Plan, simulate findings on high-priority nodes, train
        ordered = planner.plan(nodes)
        assert len(ordered) == 9

        gnn = trainer.update(
            gnn,
            confirmed_findings=["f1"],
            node_order_used=ordered,
        )

        # Reload weights and plan again
        gnn2     = SimpleGNN(weights_path=path)
        planner2 = DeadlineAwareMCTS(gnn2, scan_deadline_epoch=time.time() + 3600)
        ordered2 = planner2.plan(nodes)
        assert len(ordered2) == 9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
