"""Post-Scan GNN Fine-Tuner."""

import asyncio
import numpy as np
from typing import Any

from core.gnn_model import SimpleGNN
from core.outcome_db import OutcomeDB

class PostScanFineTuner:
    """Background fine-tuner computing binary cross-entropy gradients using finite differences."""
    
    LEARNING_RATE: float = 0.005
    N_STEPS: int = 20
    GRAD_CLIP_NORM: float = 1.0

    def fine_tune(self, gnn: SimpleGNN, scan_id: str, db: OutcomeDB) -> SimpleGNN:
        try:
            training_data = db.get_training_data(scan_id)
            if not training_data:
                return gnn

            X_list = []
            y_list = []
            for d in training_data:
                feat = d.get("features")
                if feat is not None and len(feat) == 32:
                    X_list.append(feat)
                    y_list.append(float(d["led_to_finding"]))

            if not X_list:
                return gnn

            X = np.array(X_list, dtype=np.float32)
            y = np.array(y_list, dtype=np.float32)

            eps = 1e-4

            for _ in range(self.N_STEPS):
                logits, _ = gnn.forward(X)
                loss_base = self._bce_loss(logits, y)

                grad_W2 = np.zeros_like(gnn.W2)
                for i in range(gnn.W2.shape[0]):
                    gnn.W2[i, 0] += eps
                    logits_p, _ = gnn.forward(X)
                    loss_p = self._bce_loss(logits_p, y)
                    gnn.W2[i, 0] -= eps
                    grad_W2[i, 0] = (loss_p - loss_base) / eps

                grad_a1 = np.zeros_like(gnn.a1)
                rng = np.random.default_rng(42)
                sample_idx_a1 = rng.integers(0, gnn.a1.size, size=min(16, gnn.a1.size))
                for flat_idx in sample_idx_a1:
                    r, c = divmod(int(flat_idx), gnn.a1.shape[1])
                    gnn.a1[r, c] += eps
                    logits_p, _ = gnn.forward(X)
                    loss_p = self._bce_loss(logits_p, y)
                    gnn.a1[r, c] -= eps
                    grad_a1[r, c] = (loss_p - loss_base) / eps

                grad_W1 = np.zeros_like(gnn.W1)
                sample_idx = rng.integers(0, gnn.W1.size, size=min(64, gnn.W1.size))
                for flat_idx in sample_idx:
                    r, c = divmod(int(flat_idx), gnn.W1.shape[1])
                    gnn.W1[r, c] += eps
                    logits_p, _ = gnn.forward(X)
                    loss_p = self._bce_loss(logits_p, y)
                    gnn.W1[r, c] -= eps
                    grad_W1[r, c] = (loss_p - loss_base) / eps

                grad_W1 = self._clip_gradient(grad_W1)
                grad_W2 = self._clip_gradient(grad_W2)
                grad_a1 = self._clip_gradient(grad_a1)

                gnn.W1 -= self.LEARNING_RATE * grad_W1
                gnn.W2 -= self.LEARNING_RATE * grad_W2
                gnn.a1 -= self.LEARNING_RATE * grad_a1

            try:
                gnn.save_weights()
            except Exception:
                pass
        except Exception as e:
            pass

        return gnn

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -15.0, 15.0)))

    def _bce_loss(self, logits: np.ndarray, y: np.ndarray) -> float:
        p = self._sigmoid(logits)
        p = np.clip(p, 1e-7, 1 - 1e-7)
        return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))

    @staticmethod
    def _clip_gradient(grad: np.ndarray) -> np.ndarray:
        norm = np.linalg.norm(grad)
        if norm > PostScanFineTuner.GRAD_CLIP_NORM:
            grad = grad * (PostScanFineTuner.GRAD_CLIP_NORM / norm)
        return grad

    async def run_in_background(self, gnn: SimpleGNN, scan_id: str, db: OutcomeDB) -> None:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.fine_tune, gnn, scan_id, db)
        except Exception as e:
            pass