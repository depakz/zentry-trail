"""
Deadline-aware MCTS planner for attack node validation ordering.

Uses SimpleGNN (core/gnn_model.py) policy scores blended with static
priority_score to decide which endpoints to validate first.

Exploration constant decays via a sigmoid curve:
  - Early in scan  → C ≈ 1.4  (explore broadly)
  - Near deadline  → C ≈ 0.05 (exploit best known)
"""

import time
import math
import numpy as np
from typing import List, Tuple
from dataclasses import dataclass, field

# Import the canonical SimpleGNN from gnn_model; re-export so existing code
# that does `from core.mcts_planner import SimpleGNN` keeps working.
from core.gnn_model import SimpleGNN  # noqa: F401  (re-export)


# ---------------------------------------------------------------------------
# Attack graph node
# ---------------------------------------------------------------------------

@dataclass
class AttackGraphNode:
    """
    A single node in the attack graph, representing one endpoint to validate.

    featurize() returns a 32-dim vector matching SimpleGNN.INPUT_DIM:
      [0]       priority_score
      [1]       number of confirmed findings already on this node
      [2]       1.0 if URL contains an ID-like parameter (IDOR signal)
      [3]       1.0 if URL path contains 'admin', 'payment', 'upload', 'transfer'
      [4]       1.0 if node has any output artifacts (chaining signal)
      [5:32]    reserved / zero-padded
    """
    node_id           : str
    url               : str
    priority_score    : float
    confirmed_findings: List[str]
    tech_stack        : dict = field(default_factory=dict)
    parameters        : list = field(default_factory=list)
    output_artifacts  : list = field(default_factory=list)

    def featurize(self) -> np.ndarray:
        """Return 32-dim float feature vector for GNN input."""
        features = np.zeros(32, dtype=float)

        # [0] Priority score (already a float in [0, 1])
        features[0] = float(self.priority_score)

        # [1] Confirmed findings count (log-scaled)
        features[1] = min(1.0, len(self.confirmed_findings) / 5.0)

        # [2] URL has an ID-like segment (IDOR signal)
        url_lower = self.url.lower()
        has_id = any(
            seg.isdigit() or seg.startswith("id=") or "user_id" in seg
            for seg in url_lower.replace("?", "/").replace("&", "/").replace("=", "/").split("/")
        )
        features[2] = 1.0 if has_id else 0.0

        # [3] High-value path keywords
        high_value = ("admin", "payment", "upload", "transfer", "checkout", "api/v")
        features[3] = 1.0 if any(kw in url_lower for kw in high_value) else 0.0

        # [4] Output artifacts present (useful for chain synthesis)
        features[4] = 1.0 if self.output_artifacts else 0.0

        # [5] Parameter count (normalised)
        features[5] = min(1.0, len(self.parameters) / 10.0)

        # [6:8] Tech-stack one-hot (rails/django/spring/express)
        tech = str(self.tech_stack).lower()
        features[6]  = 1.0 if "rails"   in tech else 0.0
        features[7]  = 1.0 if "django"  in tech else 0.0
        features[8]  = 1.0 if "spring"  in tech else 0.0
        features[9]  = 1.0 if "express" in tech else 0.0

        # [10:32] — reserved / future use (zeros)
        return features


# ---------------------------------------------------------------------------
# Deadline-aware MCTS planner
# ---------------------------------------------------------------------------

class DeadlineAwareMCTS:
    """
    MCTS-inspired planner that adjusts exploration vs. exploitation as the
    scan deadline approaches.

    plan() returns nodes in descending combined score order:
      combined[i] = GNN_policy_logit[i]  +  priority_score[i]

    The priority_score acts as a strong prior so that, even before the GNN
    has been trained, high-priority nodes are still processed first.
    """

    C_MAX: float = 1.4   # exploration weight at scan start
    C_MIN: float = 0.05  # exploitation weight near deadline

    def __init__(self, gnn: SimpleGNN, scan_deadline_epoch: float):
        self.gnn        = gnn
        self.deadline   = scan_deadline_epoch
        self.scan_start = time.time()

    # ------------------------------------------------------------------
    # Exploration constant
    # ------------------------------------------------------------------

    def exploration_constant(self) -> float:
        """
        Sigmoid decay from C_MAX → C_MIN as the fraction of elapsed time
        passes 60 % of the total scan window.
        """
        total    = max(1.0, self.deadline - self.scan_start)
        elapsed  = time.time() - self.scan_start
        frac     = min(1.0, elapsed / total)
        return self.C_MIN + (self.C_MAX - self.C_MIN) / (1.0 + math.exp(10.0 * (frac - 0.6)))

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------

    def plan(
        self,
        nodes         : List[AttackGraphNode],
        budget_seconds: float = 60.0,
        adjacency     : np.ndarray | None = None,
    ) -> List[AttackGraphNode]:
        """
        Return nodes in recommended validation order.

        Falls back to greedy priority ordering when:
          - deadline has < 5 s remaining
          - node list is empty
        """
        if not nodes:
            return nodes

        remaining = self.deadline - time.time()

        if remaining < 5.0:
            # Near deadline — exploit best-known priority
            return sorted(nodes, key=lambda n: n.priority_score, reverse=True)

        # Build feature matrix  (N, 32)
        features = np.array([n.featurize() for n in nodes], dtype=float)
        if features.size == 0:
            return nodes

        # GNN forward pass — pass adjacency if provided
        policy_logits, _ = self.gnn.forward(features, adjacency)

        # Blend: GNN logit  +  priority_score  +  exploration_constant * UCB-noise
        priority_scores = np.array([n.priority_score for n in nodes], dtype=float)
        c               = self.exploration_constant()
        noise           = np.random.default_rng().standard_normal(len(nodes)) * c * 0.1
        combined        = policy_logits + priority_scores + noise

        scored = sorted(zip(combined, nodes), reverse=True)
        return [node for _, node in scored]
