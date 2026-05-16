import tempfile
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.adaptive_exploit_engine import AdaptiveExploitEngine, compute_reward


class RewardTests(unittest.TestCase):
    def test_compute_reward_validated_returns_one(self):
        self.assertEqual(compute_reward(True, 0, 0, "", "", 200, False, "x"), 1.0)

    def test_compute_reward_waf_blocked_returns_zero(self):
        self.assertEqual(compute_reward(False, 0, 0, "", "", 200, True, "x"), 0.0)

    def test_compute_reward_time_delta_bonus(self):
        score = compute_reward(False, 5.0, 0.0, "", "", 200, False, "x")
        self.assertGreaterEqual(score, 0.3)
        self.assertLessEqual(score, 0.6)

    def test_compute_reward_error_bonus(self):
        score = compute_reward(False, 0.0, 0.0, "sql syntax error", "", 200, False, "x")
        self.assertGreaterEqual(score, 0.2)

    def test_compute_reward_reflection_bonus(self):
        score = compute_reward(False, 0.0, 0.0, "prefix PAYLOAD suffix", "", 200, False, "PAYLOAD")
        self.assertGreaterEqual(score, 0.15)

    def test_compute_reward_capped_at_point_eighty_five(self):
        score = compute_reward(
            False,
            5.0,
            0.0,
            "sql syntax error PAYLOAD" * 80,
            "",
            500,
            False,
            "PAYLOAD",
        )
        self.assertEqual(score, 0.85)

    def test_record_result_saves_models(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            storage_dir = Path(temp_dir) / "adaptive_exploit"
            engine = AdaptiveExploitEngine(storage_dir=str(storage_dir))
            engine.record_result("PAYLOAD", "sqli", reward=0.7, waf="unknown", tech=[])

            self.assertTrue((storage_dir / "bandit.json").exists())
            self.assertTrue((storage_dir / "grammar.json").exists())
            self.assertTrue((storage_dir / "ranker.json").exists())
            self.assertTrue((storage_dir / "corpus.json").exists())


if __name__ == "__main__":
    unittest.main()
