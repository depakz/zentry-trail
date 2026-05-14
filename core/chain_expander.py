from __future__ import annotations

from typing import Any, Dict, List

from modules.pipeline.brain.attack_chain_manager import AttackChainManager
from modules.pipeline.brain.fact_store import FactStore


class ChainExpander:
    """Simple queue expander that converts pending chain nodes into execution-ready entries."""

    def __init__(self, attack_chain_manager: AttackChainManager):
        self.attack_chain_manager = attack_chain_manager

    def check_and_expand(self, fact_store: FactStore, validation_queue: List[Dict[str, Any]]) -> int:
        nodes = self.attack_chain_manager.get_pending_exploitation_nodes()
        expanded = 0
        for node in nodes:
            validation_queue.append(
                {
                    "node_id": node.node_id,
                    "parent_validator_id": node.parent_validator_id,
                    "exploit_type": node.exploit_type,
                    "target": node.target,
                    "payload": node.payload,
                    "description": node.description,
                }
            )
            expanded += 1
        return expanded
