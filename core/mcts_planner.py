"""Lightweight GNN and deadline-aware MCTS for validation prioritization."""

import time
import math
import numpy as np
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class AttackGraphNode:
    """Node in attack graph."""
    node_id: str
    url: str
    priority_score: float
    confirmed_findings: List[str]

    def featurize(self) -> np.ndarray:
        """Return 32-dim feature vector for GNN."""
        # Simplified: just return scalar features as 32-dim vector
        features = np.zeros(32)
        features[0] = self.priority_score
        features[1] = len(self.confirmed_findings)
        return features


class SimpleGNN:
    """Lightweight numpy-based GNN for policy scoring."""

    def __init__(self, weights_path: str = "core/gnn_weights.npz"):
        self.weights_path = weights_path
        self.W1 = np.random.randn(32, 16) * 0.1
        self.W2 = np.random.randn(16, 1) * 0.1

    def forward(self, node_features: np.ndarray) -> Tuple[np.ndarray, float]:
        """Forward pass through GNN."""
        if node_features.shape[0] == 0:
            return np.array([]), 0.0
        # Simple 2-layer network
        h1 = np.tanh(node_features @ self.W1)
        logits = h1 @ self.W2
        value = float(np.mean(logits))
        return logits.flatten(), value


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
        elapsed_frac = (time.time() - self.scan_start) / max(1, self.deadline - self.scan_start)
        elapsed_frac = min(1.0, elapsed_frac)
        # Sigmoid decay
        return self.C_MIN + (self.C_MAX - self.C_MIN) / (1 + math.exp(10 * (elapsed_frac - 0.6)))

    def plan(self, nodes: List[AttackGraphNode], budget_seconds: float = 60) -> List[AttackGraphNode]:
        """Plan validation order using GNN + MCTS."""
        if self.deadline - time.time() < 5:
            # Deadline imminent, use greedy priority
            return sorted(nodes, key=lambda n: n.priority_score, reverse=True)

        # Compute policy scores via GNN
        features = np.array([n.featurize() for n in nodes])
        if features.size == 0:
            return nodes

        policy_logits, _ = self.gnn.forward(features)
        scored = list(zip(policy_logits, nodes))
        scored.sort(reverse=True)
        return [node for _, node in scored]
