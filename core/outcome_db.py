"""Scan Outcome Database."""

import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

class OutcomeDB:
    """SQLite database for tracking scan outcomes and training data."""

    def __init__(self, db_path: str = "data/outcomes.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        target TEXT,
                        started_at INTEGER,
                        completed_at INTEGER,
                        endpoint_count INTEGER,
                        finding_count INTEGER,
                        false_positive_count INTEGER DEFAULT 0
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS findings (
                        finding_id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        vuln_class TEXT,
                        endpoint_url TEXT,
                        confidence REAL,
                        confirmed INTEGER DEFAULT 0,
                        created_at INTEGER
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS node_decisions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT,
                        node_id TEXT,
                        policy_score REAL,
                        validation_order INTEGER,
                        led_to_finding INTEGER DEFAULT 0,
                        features BLOB,
                        created_at INTEGER
                    )
                ''')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS attack_win_rates (
                        strategy_id TEXT,
                        tech_stack TEXT,
                        waf_provider TEXT,
                        attempts INTEGER DEFAULT 0,
                        successes INTEGER DEFAULT 0,
                        PRIMARY KEY (strategy_id, tech_stack, waf_provider)
                    )
                ''')
                conn.commit()
        except Exception as e:
            pass

    def record_scan(self, scan_id: str, target: str, started_at: int) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO scans (scan_id, target, started_at, completed_at)
                    VALUES (?, ?, ?, ?)
                """, (scan_id, target, started_at, started_at))
                conn.commit()
        except Exception as e:
            pass

    def record_finding(self, finding_id: str, scan_id: str, vuln_class: str, url: str, confidence: float) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO findings
                    (finding_id, scan_id, vuln_class, endpoint_url, confidence, confirmed, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                """, (finding_id, scan_id, vuln_class, url, confidence, int(time.time())))
                conn.commit()
        except Exception as e:
            pass

    def record_node_decision(self, scan_id: str, node_id: str, policy_score: float, order: int, led_to_finding: int, features: Optional[np.ndarray] = None) -> None:
        try:
            if features is None:
                features = np.random.randn(32).astype(np.float32)
            feat_bytes = features.tobytes()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO node_decisions
                    (scan_id, node_id, policy_score, validation_order, led_to_finding, features, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, node_id, policy_score, order, led_to_finding, feat_bytes, int(time.time())))
                conn.commit()
        except Exception as e:
            pass

    def get_training_data(self, scan_id: str) -> List[Dict[str, Any]]:
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT node_id, policy_score, led_to_finding, features
                    FROM node_decisions
                    WHERE scan_id = ?
                    ORDER BY validation_order
                """, (scan_id,))
                for row in cursor.fetchall():
                    feat_arr = None
                    if row[3]:
                        feat_arr = np.frombuffer(row[3], dtype=np.float32)
                    results.append({
                        "node_id": row[0],
                        "policy_score": row[1],
                        "led_to_finding": row[2],
                        "features": feat_arr
                    })
        except Exception as e:
            pass
        return results

    def update_win_rate(self, strategy_id: str, tech_stack: str, waf_provider: str, success: bool) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO attack_win_rates (strategy_id, tech_stack, waf_provider, attempts, successes)
                    VALUES (?, ?, ?, 1, ?)
                    ON CONFLICT(strategy_id, tech_stack, waf_provider) DO UPDATE SET
                    attempts = attempts + 1,
                    successes = successes + excluded.successes
                """, (strategy_id, tech_stack, waf_provider, 1 if success else 0))
                conn.commit()
        except Exception as e:
            pass

    def get_win_rates(self, tech_stack: str, waf_provider: str) -> List[Dict[str, Any]]:
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT strategy_id, successes * 1.0 / MAX(attempts, 1) as success_rate, attempts
                    FROM attack_win_rates
                    WHERE tech_stack = ? AND waf_provider = ?
                """, (tech_stack, waf_provider))
                for row in cursor.fetchall():
                    results.append({"strategy_id": row[0], "success_rate": row[1], "attempts": row[2]})
        except Exception as e:
            pass
        return results