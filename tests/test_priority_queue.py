import asyncio
from avvp.services.priority_queue.service import RedisPriorityQueue


def test_compute_score_ordering():
    p1 = {'parameter_weight': 1.0, 'exposure': 0.0, 'historical_rate': 0.0, 'gnn_similarity': 0.0}
    p2 = {'parameter_weight': 0.5, 'exposure': 1.0, 'historical_rate': 0.5, 'gnn_similarity': 0.2}
    s1 = RedisPriorityQueue.compute_score(p1)
    s2 = RedisPriorityQueue.compute_score(p2)
    assert isinstance(s1, float) and isinstance(s2, float)

    # Expect s2 > s1 because exposure and historical_rate add up
    assert s2 >= s1
