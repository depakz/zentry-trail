import os
import sqlite3
import pytest
import numpy as np

from core.outcome_db import OutcomeDB
from core.attack_selector import AttackSelector

def test_outcome_db_crud(tmp_path):
    db_path = str(tmp_path / "outcomes.db")
    db = OutcomeDB(db_path)

    db.record_scan("scan_1", "example.com", 1000)
    db.record_finding("find_1", "scan_1", "xss", "example.com", 0.9)
    db.record_node_decision("scan_1", "node_1", 0.8, 1, 1, np.ones(32, dtype=np.float32))

    data = db.get_training_data("scan_1")
    assert len(data) == 1
    assert data[0]["node_id"] == "node_1"
    assert data[0]["led_to_finding"] == 1
    assert np.array_equal(data[0]["features"], np.ones(32, dtype=np.float32))

    db.update_win_rate("xss_dom", "react", "cloudflare", True)
    db.update_win_rate("xss_dom", "react", "cloudflare", False)

    win_rates = db.get_win_rates("react", "cloudflare")
    assert len(win_rates) == 1
    assert win_rates[0]["strategy_id"] == "xss_dom"
    assert win_rates[0]["attempts"] == 2
    assert win_rates[0]["success_rate"] == 0.5

def test_attack_selector(tmp_path):
    db = OutcomeDB(str(tmp_path / "outcomes.db"))
    db.update_win_rate("stored", "react", "none", True)
    db.update_win_rate("dom", "react", "none", False)
    selector = AttackSelector(db)
    ranked = selector.rank_payloads("XSS", "react", "none")
    assert ranked[0] == "stored"