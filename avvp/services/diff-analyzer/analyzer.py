from typing import Dict, Any

class DiffResult:
    def __init__(self, anomaly_score: float, changed_fields: Dict[str, Any], new_keywords: list):
        self.anomaly_score = anomaly_score
        self.changed_fields = changed_fields
        self.new_keywords = new_keywords


def analyze(baseline: Dict[str, Any], response: Dict[str, Any]) -> DiffResult:
    # baseline and response contain: status_code, body, latency, headers
    score = 0.0
    changed = {}
    new_kw = []

    if baseline is None:
        return DiffResult(1.0, {'note':'no baseline'}, [])

    # status code delta
    if baseline.get('status_code') != response.get('status_code'):
        score += 0.4
        changed['status_code'] = (baseline.get('status_code'), response.get('status_code'))

    # body length delta
    bl = len(baseline.get('body',''))
    rl = len(response.get('body',''))
    if bl > 0:
        delta = abs(rl - bl) / bl
        if delta > 0.2:
            score += 0.3
            changed['body_len_delta'] = delta

    # latency delta
    base_lat = baseline.get('latency', 0)
    resp_lat = response.get('latency', 0)
    if base_lat > 0:
        lat_delta = (resp_lat - base_lat) / max(1, base_lat)
        if lat_delta > 0.5:
            score += 0.2
            changed['latency_delta'] = lat_delta

    # heuristic keyword detection
    keywords = ['error', 'exception', 'sql', 'stacktrace']
    body = response.get('body','').lower()
    for k in keywords:
        if k in body and k not in baseline.get('body','').lower():
            score += 0.2
            new_kw.append(k)

    score = min(1.0, score)
    return DiffResult(score, changed, new_kw)
