import os
import joblib
import time
from typing import Any, Dict, List

try:
    import torch
    HAS_TORCH = True
except Exception:
    HAS_TORCH = False

from avvp.services.embedding_reasoner.reasoner import EmbeddingReasoner

class GNNTrainer:
    def __init__(self, out_dir: str = None):
        self.out_dir = out_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'models')
        os.makedirs(self.out_dir, exist_ok=True)
        self.embedder = EmbeddingReasoner()

    def train_from_findings(self, findings: List[Dict[str, Any]]) -> Dict:
        """Train a simple embedding-based model over findings.
        This is a lightweight placeholder: compute embeddings for each finding's `message`
        and store the centroid per `vuln_class`.
        """
        texts = [f.get('message', '') for f in findings]
        emb = self.embedder.embed(texts)
        by_class = {}
        for fvec, f in zip(emb, findings):
            cls = f.get('vuln_class', 'unknown')
            by_class.setdefault(cls, []).append(fvec)
        centroids = {}
        for cls, vecs in by_class.items():
            import numpy as np
            arr = np.array(vecs, dtype=float)
            centroids[cls] = arr.mean(axis=0).tolist()
        model = {'centroids': centroids, 'trained_at': time.time()}
        return model

    def persist_model(self, model: Dict, name: str) -> str:
        fname = f"{int(time.time())}-{name}.joblib"
        out = os.path.join(self.out_dir, fname)
        joblib.dump(model, out)
        return out
