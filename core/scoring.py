"""
score = severity_weight + exploitability + exposure
Range: 0–10
"""
SEV = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

def score_finding(finding: dict) -> float:
    sev = SEV.get(finding.get("severity", "info"), 1)
    expl = 3 if finding.get("validated") else 0
    expo = 2 if finding.get("public", True) else 1
    raw = sev * 0.6 + expl + expo * 0.5
    return round(min(raw, 10.0), 2)
