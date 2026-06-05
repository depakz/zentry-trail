from typing import List, Dict, Any

class ChainRanker:
    def __init__(self):
        pass

    def score_chain(self, chain: List[Dict[str,Any]]) -> float:
        # chain is list of steps with attributes exploitability, impact, novelty
        score = 0.0
        for step in chain:
            exploit = step.get('exploitability', 0.5)
            impact = step.get('impact', 0.5)
            novelty = step.get('novelty', 0.5)
            score += exploit * impact * (1 + novelty)
        # normalize
        return score / max(1, len(chain))

    def rank(self, chains: List[List[Dict[str,Any]]]) -> List[Dict[str,Any]]:
        scored = []
        for c in chains:
            s = self.score_chain(c)
            scored.append({'chain': c, 'score': s})
        scored.sort(key=lambda x: x['score'], reverse=True)
        return scored
