"""Lightweight GNN and deadline-aware MCTS for validation prioritization."""

import time
import math
import numpy as np
from typing import Dict, List, Tuple
from core.gnn_model import SimpleGNN
from core.attack_graph import AttackGraphNode


class DeadlineAwareMCTS:
    """MCTS with deadline-aware exploration vs exploitation tradeoff."""

    C_MAX = 1.4
    C_MIN = 0.05

    def __init__(self, gnn: SimpleGNN, scan_deadline_epoch: float):
        self.gnn = gnn
        self.deadline = scan_deadline_epoch
        self.scan_start = time.time()

    def exploration_constant(self) -> float:
        """Decay exploration weight as deadline approaches."""
        current_time = time.time()
        total_time = max(1.0, self.deadline - self.scan_start)
        elapsed_frac = (current_time - self.scan_start) / total_time
        elapsed_frac = min(1.0, max(0.0, elapsed_frac))
        # Sigmoid decay
        try:
            decay = 1.0 / (1.0 + math.exp(10.0 * (elapsed_frac - 0.6)))
        except OverflowError:
            decay = 0.0
        return self.C_MIN + (self.C_MAX - self.C_MIN) * decay

    def plan(self, nodes: List[AttackGraphNode], budget_seconds: float = 60) -> List[AttackGraphNode]:
        """Plan validation order using GNN + MCTS."""
        time_left = self.deadline - time.time()
        if time_left < 5.0:
            return sorted(nodes, key=lambda n: n.priority_score, reverse=True)

        if not nodes:
            return []

        # Compute policy scores via GNN
        features = np.array([n.featurize() for n in nodes], dtype=np.float32)
        policy_logits, _ = self.gnn.forward(features)
        
        exp_c = self.exploration_constant()
        scores = policy_logits + exp_c * np.random.randn(len(nodes))
        
        scored = list(zip(scores, nodes))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [node for _, node in scored]
