"""Outcome database and self-training loop for GNN improvement."""

import sqlite3
import time
from pathlib import Path
from typing import List, Dict, Any, Optional


class OutcomeDB:
    """SQLite database for tracking scan outcomes and training data."""

    def __init__(self, db_path: str = "data/outcomes.db"):
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # For :memory: we keep a single persistent connection because each
        # sqlite3.connect(':memory:') call creates a brand-new empty database.
        self._conn = sqlite3.connect(db_path) if db_path == ":memory:" else None
        self._init_schema()

    def _get_conn(self):
        """Return existing connection (for :memory:) or open a new one."""
        if self._conn is not None:
            return self._conn, False  # (conn, should_close)
        return sqlite3.connect(self.db_path), True

    def _init_schema(self):
        """Initialize database schema."""
        conn, should_close = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT,
                    started_at INTEGER,
                    completed_at INTEGER,
                    endpoint_count INTEGER,
                    finding_count INTEGER,
                    false_positive_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    vuln_class TEXT,
                    endpoint_url TEXT,
                    confidence REAL,
                    confirmed INTEGER DEFAULT 0,
                    created_at INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS node_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    node_id TEXT,
                    policy_score REAL,
                    validation_order INTEGER,
                    led_to_finding INTEGER DEFAULT 0,
                    created_at INTEGER
                )
            """)
            conn.commit()
        finally:
            if should_close:
                conn.close()

    def record_scan(self, scan_id: str, target: str, started_at: int):
        """Record scan start."""
        conn, should_close = self._get_conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO scans (scan_id, target, started_at)
                VALUES (?, ?, ?)
            """, (scan_id, target, started_at))
            conn.commit()
        finally:
            if should_close:
                conn.close()

    def record_finding(self, finding_id: str, scan_id: str, vuln_class: str, url: str, confidence: float):
        """Record a finding."""
        conn, should_close = self._get_conn()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO findings
                (finding_id, scan_id, vuln_class, endpoint_url, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (finding_id, scan_id, vuln_class, url, confidence, int(time.time())))
            conn.commit()
        finally:
            if should_close:
                conn.close()

    def record_node_decision(self, scan_id: str, node_id: str, policy_score: float, order: int, led_to_finding: int):
        """Record a node validation decision."""
        conn, should_close = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO node_decisions
                (scan_id, node_id, policy_score, validation_order, led_to_finding, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, node_id, policy_score, order, led_to_finding, int(time.time())))
            conn.commit()
        finally:
            if should_close:
                conn.close()

    def get_training_data(self, scan_id: str) -> List[Dict]:
        """Get training data (node decisions + outcomes) for a scan."""
        conn, should_close = self._get_conn()
        try:
            cursor = conn.execute("""
                SELECT nd.node_id, nd.policy_score, nd.led_to_finding
                FROM node_decisions nd
                WHERE nd.scan_id = ?
                ORDER BY nd.validation_order
            """, (scan_id,))
            rows = cursor.fetchall()
            return [
                {"node_id": row[0], "policy_score": row[1], "led_to_finding": row[2]}
                for row in rows
            ]
        finally:
            if should_close:
                conn.close()



class PostScanFineTuner:
    """Fine-tune GNN weights after scan based on outcome."""

    def __init__(self):
        self.learning_rate = 0.001
        self.n_steps = 10

    def fine_tune(self, gnn, scan_id: str, db: OutcomeDB):
        """Update GNN weights based on scan results."""
        import numpy as np
        training_data = db.get_training_data(scan_id)
        if len(training_data) < 2:
            return gnn

        # Extract labels: 1 if node led to finding, 0 otherwise
        labels = np.array([d["led_to_finding"] for d in training_data], dtype=float)
        policy_scores = np.array([d["policy_score"] for d in training_data], dtype=float)

        # Gradient update: push W2 to separate positive and negative examples
        # Use error signal: error[i] = labels[i] - sigmoid(policy_scores[i])
        def sigmoid(x):
            return 1.0 / (1.0 + np.exp(-np.clip(x, -10, 10)))

        for _ in range(self.n_steps):
            preds = sigmoid(policy_scores)
            errors = labels - preds  # shape: (N,)
            # Gradient for W2: sum of (error * policy_score) as a scalar signal
            grad = np.mean(errors * policy_scores)
            # Apply gradient to W2 (nudge all weights in same direction)
            gnn.W2 = gnn.W2 + self.learning_rate * grad

        return gnn


class AttackSelector:
    """Select payload strategies based on historical win rates."""

    def __init__(self, db: OutcomeDB):
        self.db = db

    def rank_payloads(self, vuln_class: str, tech_stack: str) -> List[str]:
        """Rank payload strategies by success rate."""
        # Simplified: return fixed order for now
        strategies = {
            "SQLI": ["time_based", "union", "boolean_blind", "error_based"],
            "XSS": ["dom", "reflected", "stored", "svg"],
            "CMDI": ["semicolon", "pipe", "ampersand", "backtick"],
        }
        return strategies.get(vuln_class, ["generic"])
