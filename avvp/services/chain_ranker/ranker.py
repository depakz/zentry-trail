from typing import List, Dict, Any

class ChainRanker:
    def __init__(self):
        pass

    def score_chain(self, chain: List[Dict[str,Any]]) -> float:
        score = 0.0
        for step in chain:
            # support steps as either dict or list-of-dicts
            if isinstance(step, list):
                if not step:
                    continue
                step_obj = step[0] if isinstance(step[0], dict) else {}
            elif isinstance(step, dict):
                step_obj = step
            else:
                continue
            exploit = step_obj.get('exploitability', 0.5)
            impact = step_obj.get('impact', 0.5)
            novelty = step_obj.get('novelty', 0.5)
            score += exploit * impact * (1 + novelty)
        return score / max(1, len(chain))

    def rank(self, chains: List[List[Dict[str,Any]]]) -> List[Dict[str,Any]]:
        scored = []
        for c in chains:
            s = self.score_chain(c)
            scored.append({'chain': c, 'score': s})
        scored.sort(key=lambda x: x['score'], reverse=True)
        return scored
