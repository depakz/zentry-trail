try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    HAS_ST = True
except Exception:
    HAS_ST = False
    import hashlib

from typing import List, Dict, Any

class EmbeddingReasoner:
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        if HAS_ST:
            self.model = SentenceTransformer(model_name)
        else:
            self.model = None

    def embed(self, texts: List[str]):
        if HAS_ST:
            return self.model.encode(texts, convert_to_numpy=True)
        # fallback: use hash-based pseudo-embeddings
        vecs = []
        for t in texts:
            h = hashlib.sha256(t.encode()).digest()[:16]
            arr = [b/255.0 for b in h]
            vecs.append(arr)
        return vecs

    def most_similar(self, query: str, candidates: List[str], top_k: int = 3):
        qv = self.embed([query])[0]
        cvs = self.embed(candidates)
        # compute cosine similarity
        def cos(a,b):
            import math
            na = math.sqrt(sum(x*x for x in a))
            nb = math.sqrt(sum(x*x for x in b))
            if na==0 or nb==0:
                return 0
            return sum(x*y for x,y in zip(a,b))/(na*nb)
        sims = [(c, cos(qv, cv)) for c,cv in zip(candidates, cvs)]
        sims.sort(key=lambda x: x[1], reverse=True)
        return sims[:top_k]
