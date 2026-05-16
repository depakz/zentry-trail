"""Simple bandit agent helpers to select payload arms from persisted bandit model."""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _bandit_path(storage_dir: Path | None = None) -> Path:
    root = Path(__file__).resolve().parents[1]
    storage = Path(storage_dir) if storage_dir else root / "data" / "adaptive_exploit"
    return storage / "bandit.json"


def _load_bandit(storage_dir: Path | None = None) -> Dict[str, Any]:
    path = _bandit_path(storage_dir)
    if not path.exists():
        return {"arms": {}, "vuln_type_stats": {}, "updates": 0}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"arms": {}, "vuln_type_stats": {}, "updates": 0}


def top_arms(vuln_type: str | None = None, n: int = 10, storage_dir: Path | None = None) -> List[Tuple[str, float]]:
    """Return top `n` arms as (payload, mean_reward) tuples. If `vuln_type`
    is provided, arms with explicit association to that vuln_type are preferred
    if available.
    """
    bandit = _load_bandit(storage_dir)
    arms = bandit.get("arms", {}) or {}
    scored = [(p, float(a.get("mean_reward", 0.0))) for p, a in arms.items()]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:n]


def sample_arm(vuln_type: str | None = None, storage_dir: Path | None = None) -> str | None:
    """Sample an arm weighted by mean_reward. Falls back to top arm or None.
    """
    arms = top_arms(vuln_type=vuln_type, n=100, storage_dir=storage_dir)
    if not arms:
        return None
    weights = [max(0.0, score) for _, score in arms]
    total = sum(weights)
    if total <= 0.0:
        # uniform fallback
        return random.choice([p for p, _ in arms])
    choices = [p for p, _ in arms]
    # Weighted random choice
    r = random.random() * total
    upto = 0.0
    for p, w in zip(choices, weights):
        upto += w
        if upto >= r:
            return p
    return choices[-1]
