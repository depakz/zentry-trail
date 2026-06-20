"""Historical Win-Rate Attack Strategy Selector."""

from typing import List
from core.outcome_db import OutcomeDB

class AttackSelector:
    """Select payload strategies based on historical win rates."""

    def __init__(self, db: OutcomeDB):
        self.db = db

    def rank_payloads(self, vuln_class: str, tech_stack: str, waf_detected: str) -> List[str]:
        """Rank payload strategies by success rate with alphabetical fallback."""
        default_strategies = {
            "SQLI": ["boolean_blind", "error_based", "time_based", "union"],
            "XSS": ["dom", "reflected", "stored", "svg"],
            "CMDI": ["ampersand", "backtick", "pipe", "semicolon"],
            "SSRF": ["cloud_metadata", "dns_rebinding", "ipv6_bypass", "localhost"],
        }
        defaults = sorted(default_strategies.get(vuln_class, ["generic"]))

        try:
            win_rates = self.db.get_win_rates(tech_stack, waf_detected)
            if not win_rates:
                return defaults
            strategy_scores = {r["strategy_id"]: r["success_rate"] for r in win_rates}
            return sorted(defaults, key=lambda s: strategy_scores.get(s, 0.0), reverse=True)
        except Exception as e:
            return defaults