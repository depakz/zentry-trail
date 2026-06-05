import redis.asyncio as redis
import json
import time
from typing import Dict

class ExploitStateMachine:
    STATES = ["discovered", "planned", "in_progress", "confirmed",
              "chain_exploring", "chain_confirmed", "evidence_sealed"]

    def __init__(self, redis_url: str = "redis://127.0.0.1:6379/0"):
        self.redis = redis.from_url(redis_url)

    def valid_transition(self, current: str, new: str) -> bool:
        if current is None:
            return True
        try:
            ci = self.STATES.index(current)
            ni = self.STATES.index(new)
            return ni >= ci
        except Exception:
            return False

    async def transition(self, finding_id: str, new_state: str, evidence: Dict = None):
        key = f"state:{finding_id}"
        current = await self.redis.get(key)
        current_s = current.decode() if current else None
        if not self.valid_transition(current_s, new_state):
            raise ValueError(f"Invalid transition {current_s} -> {new_state}")
        await self.redis.set(key, new_state)
        hist_key = f"history:{finding_id}"
        entry = json.dumps({"state": new_state, "evidence": evidence or {}, "timestamp": time.time()})
        await self.redis.lpush(hist_key, entry)
