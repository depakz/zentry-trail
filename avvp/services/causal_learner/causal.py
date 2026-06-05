from typing import List, Tuple, Dict

class CausalLearner:
    def __init__(self):
        pass

    def fit(self, finding_pairs: List[Tuple[str, str]]):
        counts = {}
        total_from = {}
        for a, b in finding_pairs:
            counts.setdefault((a,b), 0)
            counts[(a,b)] += 1
            total_from.setdefault(a, 0)
            total_from[a] += 1
        self.probs = {}
        for (a,b), c in counts.items():
            self.probs[(a,b)] = c / max(1, total_from.get(a,1))

    def p(self, a: str, b: str) -> float:
        return self.probs.get((a,b), 0.0)

    def suggest_rules(self, threshold: float = 0.3) -> Dict[str, List[Tuple[str,float]]]:
        rules = {}
        for (a,b), p in self.probs.items():
            if p >= threshold:
                rules.setdefault(a,[]).append((b,p))
        return rules
