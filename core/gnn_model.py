"""
Lightweight numpy-based Graph Neural Network for attack node policy scoring.

Architecture: 2-layer Graph Attention Network approximated with numpy.
  Input:  node features  (N x 32)
  Hidden: W1             (32 x 64)  — tanh activation + adjacency aggregation
  Output: policy logits  (N x 1)    — per-node expected value
          value estimate (scalar)   — overall graph value

Pre-trained weights are loaded from core/gnn_weights.npz when available.
Falls back to reproducible random init (seed=42) if the file is absent —
the model still runs but improves only after PostScanTrainer updates weights.
"""

import os
import numpy as np
from typing import Tuple


class SimpleGNN:
    """
    2-layer Graph Attention Network approximated with numpy.

    Forward pass:
      1. Aggregate neighbour features:  X_agg = A_norm @ X  (A_norm = row-normalised adjacency + I)
      2. Layer 1:                        H1 = tanh(X_agg @ W1)
      3. Layer 2:                        logits = H1 @ W2
      4. Value estimate:                 v = mean(logits)
    """

    # Weight dimensions match the 32-dim feature vector defined in AttackGraphNode.featurize()
    INPUT_DIM  = 32
    HIDDEN_DIM = 64
    OUTPUT_DIM = 1

    def __init__(self, weights_path: str = "core/gnn_weights.npz"):
        self.weights_path = weights_path
        self.W1: np.ndarray = None   # (32, 64)
        self.W2: np.ndarray = None   # (64, 1)
        self._load_weights()

    # ------------------------------------------------------------------
    # Weight management
    # ------------------------------------------------------------------

    def _load_weights(self) -> None:
        """Load weights from npz file; fall back to reproducible random init."""
        if os.path.exists(self.weights_path):
            try:
                data = np.load(self.weights_path)
                self.W1 = data["W1"]
                self.W2 = data["W2"]
                return
            except Exception:
                pass  # corrupt file — fall through to random init

        # Reproducible random init (seed=42)
        rng = np.random.default_rng(42)
        self.W1 = rng.standard_normal((self.INPUT_DIM, self.HIDDEN_DIM)) * 0.1
        self.W2 = rng.standard_normal((self.HIDDEN_DIM, self.OUTPUT_DIM)) * 0.1

    def save_weights(self) -> None:
        """Persist current weights to disk."""
        os.makedirs(os.path.dirname(self.weights_path) or ".", exist_ok=True)
        np.savez(self.weights_path, W1=self.W1, W2=self.W2)

    # ------------------------------------------------------------------
    # Forward pass
    # ------------------------------------------------------------------

    def forward(
        self,
        node_features: np.ndarray,
        adjacency: np.ndarray | None = None,
    ) -> Tuple[np.ndarray, float]:
        """
        Run a forward pass through the GNN.

        Parameters
        ----------
        node_features : ndarray, shape (N, 32)
        adjacency     : ndarray, shape (N, N)  optional — identity if not provided

        Returns
        -------
        policy_logits : ndarray, shape (N,)   — per-node score
        value         : float                 — graph-level value estimate
        """
        N = node_features.shape[0]
        if N == 0:
            return np.array([]), 0.0

        # Build row-normalised adjacency + self-loops
        if adjacency is not None and adjacency.shape == (N, N):
            A = adjacency + np.eye(N)
        else:
            A = np.eye(N)

        # Row-normalise so aggregation is a weighted average, not a sum
        row_sums = A.sum(axis=1, keepdims=True)
        row_sums = np.where(row_sums == 0, 1.0, row_sums)   # avoid divide-by-zero
        A_norm = A / row_sums

        # Layer 1: aggregate neighbours then project
        X_agg = A_norm @ node_features       # (N, 32)
        H1    = np.tanh(X_agg @ self.W1)    # (N, 64)

        # Layer 2: policy logits
        logits = H1 @ self.W2               # (N, 1)
        value  = float(np.mean(logits))

        return logits.flatten(), value       # (N,), scalar

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def weights_loaded_from_disk(self) -> bool:
        """True when the weights file exists and was successfully loaded."""
        return os.path.exists(self.weights_path)

    def __repr__(self) -> str:
        status = "trained" if self.weights_loaded_from_disk() else "random-init"
        return (
            f"SimpleGNN(dims={self.INPUT_DIM}→{self.HIDDEN_DIM}→{self.OUTPUT_DIM}, "
            f"weights={status}, path={self.weights_path!r})"
        )
