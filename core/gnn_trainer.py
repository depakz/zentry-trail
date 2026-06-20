"""
Post-scan GNN trainer — updates SimpleGNN weights after each scan completes.

Strategy
--------
After a scan, we know:
  - which nodes were validated (node_order_used)
  - which nodes led to confirmed findings (confirmed_findings)

We use this signal to run a lightweight supervised gradient descent:
  - Label  y[i] = 1.0 if node i produced a confirmed finding, else 0.0
  - Loss   = binary cross-entropy(sigmoid(policy_logit[i]), y[i])
  - Gradient approximated with finite differences (no autograd needed)
  - Gradient clipped to L2-norm 1.0 to prevent divergence
  - Weights saved back to gnn_weights.npz after training

Running in 10 steps at lr=0.001 is intentionally conservative — we want
the model to improve gradually across many scans rather than overfit to one.
"""

import numpy as np
from typing import List

from core.gnn_model import SimpleGNN


class PostScanTrainer:
    """
    Fine-tune SimpleGNN weights based on confirmed findings after a scan.

    Usage
    -----
    trainer = PostScanTrainer()
    updated_gnn = trainer.update(gnn, confirmed_findings, node_order_used)
    """

    LEARNING_RATE : float = 0.001
    N_STEPS       : int   = 10
    GRAD_CLIP_NORM: float = 1.0

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def update(
        self,
        gnn            : SimpleGNN,
        confirmed_findings: List[str],          # finding_ids (or node_ids) confirmed
        node_order_used: list,                  # AttackGraphNode list in plan order
    ) -> SimpleGNN:
        """
        Nudge GNN weights towards policies that led to confirmed findings.

        Parameters
        ----------
        gnn               : SimpleGNN to update in-place
        confirmed_findings: list of finding IDs (or node IDs) that were confirmed
        node_order_used   : ordered list of AttackGraphNode (or dicts) visited

        Returns
        -------
        Updated SimpleGNN (same object, weights mutated and saved).
        """
        if not node_order_used:
            return gnn

        # ── Build feature matrix and binary labels ──────────────────────
        confirmed_set = set(str(f) for f in confirmed_findings)

        features_list = []
        labels_list   = []

        for node in node_order_used:
            # Support both AttackGraphNode dataclass and plain dicts
            if hasattr(node, "featurize"):
                feat     = node.featurize()
                node_key = str(getattr(node, "node_id", ""))
                # Also accept URL as key
                url_key  = str(getattr(node, "url", ""))
                # A node "led to finding" if its ID or any of its confirmed_findings matches
                node_findings = getattr(node, "confirmed_findings", [])
                led = (
                    node_key in confirmed_set
                    or url_key in confirmed_set
                    or any(str(f) in confirmed_set for f in node_findings)
                    or bool(node_findings)   # node already has findings → positive
                )
            else:
                # dict-style node
                feat     = np.zeros(SimpleGNN.INPUT_DIM)
                node_key = str(node.get("node_id", ""))
                led      = node_key in confirmed_set

            features_list.append(feat)
            labels_list.append(1.0 if led else 0.0)

        X = np.array(features_list, dtype=float)   # (N, 32)
        y = np.array(labels_list,   dtype=float)   # (N,)

        if X.shape[0] == 0 or np.all(y == y[0]):
            # Nothing to learn: no samples or all same label
            return gnn

        # ── Gradient descent (finite-difference approx) ─────────────────
        eps = 1e-4   # perturbation for finite differences

        for _ in range(self.N_STEPS):
            logits, _ = gnn.forward(X)                # (N,)
            loss_base = self._bce_loss(logits, y)

            # ── Gradient for W2 (64, 1) ────────────────────────────────
            grad_W2 = np.zeros_like(gnn.W2)
            for i in range(gnn.W2.shape[0]):
                gnn.W2[i, 0] += eps
                logits_p, _ = gnn.forward(X)
                loss_p = self._bce_loss(logits_p, y)
                gnn.W2[i, 0] -= eps
                grad_W2[i, 0] = (loss_p - loss_base) / eps

            # ── Gradient for a1
            grad_a1 = np.zeros_like(gnn.a1)
            rng = np.random.default_rng()
            sample_idx_a1 = rng.integers(0, gnn.a1.size, size=min(16, gnn.a1.size))
            for flat_idx in sample_idx_a1:
                r, c = divmod(int(flat_idx), gnn.a1.shape[1])
                gnn.a1[r, c] += eps
                logits_p, _ = gnn.forward(X)
                loss_p = self._bce_loss(logits_p, y)
                gnn.a1[r, c] -= eps
                grad_a1[r, c] = (loss_p - loss_base) / eps

            # ── Gradient for W1 (32, 64) — sample 8 random elements ───
            # Full finite-difference over W1 (32×64=2048 elements) would be
            # slow; sampling keeps it fast while still improving the model.
            grad_W1 = np.zeros_like(gnn.W1)
            sample_idx = rng.integers(0, gnn.W1.size, size=min(64, gnn.W1.size))
            for flat_idx in sample_idx:
                r, c = divmod(int(flat_idx), gnn.W1.shape[1])
                gnn.W1[r, c] += eps
                logits_p, _ = gnn.forward(X)
                loss_p = self._bce_loss(logits_p, y)
                gnn.W1[r, c] -= eps
                grad_W1[r, c] = (loss_p - loss_base) / eps

            # ── Clip gradients ─────────────────────────────────────────
            grad_W1 = self._clip_gradient(grad_W1)
            grad_W2 = self._clip_gradient(grad_W2)
            grad_a1 = self._clip_gradient(grad_a1)

            # ── Gradient step (descend — subtract gradient) ────────────
            gnn.W1 -= self.LEARNING_RATE * grad_W1
            gnn.W2 -= self.LEARNING_RATE * grad_W2
            gnn.a1 -= self.LEARNING_RATE * grad_a1

        # ── Persist updated weights ──────────────────────────────────────
        try:
            gnn.save_weights()
        except Exception:
            pass   # non-fatal — weights are updated in memory regardless

        return gnn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -15.0, 15.0)))

    def _bce_loss(self, logits: np.ndarray, y: np.ndarray) -> float:
        """Binary cross-entropy loss."""
        p = self._sigmoid(logits)
        p = np.clip(p, 1e-7, 1 - 1e-7)
        return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))

    @staticmethod
    def _clip_gradient(grad: np.ndarray) -> np.ndarray:
        """Clip gradient array so its L2 norm ≤ GRAD_CLIP_NORM."""
        norm = np.linalg.norm(grad)
        if norm > PostScanTrainer.GRAD_CLIP_NORM:
            grad = grad * (PostScanTrainer.GRAD_CLIP_NORM / norm)
        return grad
