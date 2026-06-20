import os
import numpy as np
import pytest

from core.outcome_db import OutcomeDB
from core.gnn_model import SimpleGNN
from core.gnn_fine_tuner import PostScanFineTuner

def test_fine_tuner_optimization(tmp_path):
    db_path = str(tmp_path / "outcomes.db")
    db = OutcomeDB(db_path)
    gnn_path = str(tmp_path / "gnn.npz")
    gnn = SimpleGNN(gnn_path)

    # Record training data
    db.record_node_decision("scan_1", "node_1", 0.5, 1, 1, np.ones(32, dtype=np.float32))
    db.record_node_decision("scan_1", "node_2", 0.5, 2, 0, np.zeros(32, dtype=np.float32))

    tuner = PostScanFineTuner()
    
    W1_orig = gnn.W1.copy()
    W2_orig = gnn.W2.copy()
    
    gnn = tuner.fine_tune(gnn, "scan_1", db)
    
    assert not np.array_equal(gnn.W1, W1_orig)
    assert not np.array_equal(gnn.W2, W2_orig)
    
    assert tuner.fine_tune(gnn, "empty_scan", db) is gnn