from typing import List, Dict, Any
import math

class AttackSelector:
    def __init__(self):
        pass

    def rank_strategies(self, endpoint_profile: Dict[str, Any], gnn_probs: List[float]) -> List[Dict[str, Any]]:
        # Combine GNN policy probabilities with heuristic historical success
        strategies = endpoint_profile.get('candidate_attacks', ['xss','sqli','ssrf'])
        historical = endpoint_profile.get('historical_success', {})
        ranked = []
        for i, atk in enumerate(strategies):
            gprob = gnn_probs[i] if i < len(gnn_probs) else 0.01
            hist = historical.get(atk, 0.0)
            score = 0.7 * gprob + 0.3 * hist
            ranked.append({'attack': atk, 'score': score, 'payload_variant': 0})
        ranked.sort(key=lambda x: x['score'], reverse=True)
        return ranked
