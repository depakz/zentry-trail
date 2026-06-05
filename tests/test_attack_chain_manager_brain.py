from modules.pipeline.brain.attack_chain_manager import AttackChainManager
from modules.pipeline.brain.fact_store import FactCategory


class FakeFact:
    def __init__(self, key, value):
        self.key = key
        self.value = value


class FakeFactStore:
    def __init__(self, facts_by_category=None):
        self.facts_by_category = facts_by_category or {category: [] for category in FactCategory}
        self.calls = []

    def get_facts_by_category(self, category):
        return self.facts_by_category.get(category, [])

    def prerequisites_met(self, prerequisites):
        required = prerequisites.required_facts
        for category, keys in required.items():
            facts = self.facts_by_category.get(category, [])
            values = {fact.key for fact in facts} | {str(fact.value) for fact in facts}
            if not all(key in values for key in keys):
                return False
        return True

    def add_confirmed_vulnerability(self, **kwargs):
        self.calls.append(("add_confirmed_vulnerability", kwargs))
        return kwargs

    def add_credential(self, **kwargs):
        self.calls.append(("add_credential", kwargs))
        return kwargs

    def add_fact(self, fact):
        self.calls.append(("add_fact", fact))
        return fact


def test_attack_chain_manager_triggers_callbacks_and_serializes():
    store = FakeFactStore()
    manager = AttackChainManager(store)

    emitted = []
    manager.register_chain_callback(lambda node: emitted.append(node.to_dict()))

    manager.validator_completed("port_discovery")
    manager.validator_completed("unauth_service_validator")
    manager.validator_completed("cred_leak_validator")

    assert emitted and emitted[0]["node_id"] == "auth_bypass_rce"
    assert manager.get_active_chains()
    assert manager.get_pending_exploitation_nodes() == []

    manager.disable_chain("chain_a")
    assert all(chain.chain_id != "chain_a_credential_escalation" for chain in manager.get_active_chains())
    manager.enable_chain("chain_a")
    exported = manager.export_chains()
    assert exported["chain_a"]["name"] == "Port Discovery to Credential-Based Attack"

    stats = manager.get_chain_statistics()
    assert stats["total_chains"] >= 5
    assert stats["completed_validators"] == 3


def test_attack_chain_manager_returns_emitted_nodes_without_consuming_preview():
    store = FakeFactStore()
    manager = AttackChainManager(store)

    emitted = manager.validator_completed("port_discovery")
    assert emitted == []

    manager.validator_completed("unauth_service_validator")
    emitted = manager.validator_completed("cred_leak_validator")

    assert emitted
    assert emitted[0].node_id == "auth_bypass_rce"
    assert manager.get_pending_exploitation_nodes() == []


def test_attack_chain_manager_fact_chains_and_parsing():
    facts = {category: [FakeFact("ssti_confirmed", "yes")] for category in FactCategory}
    store = FakeFactStore(facts)
    manager = AttackChainManager(store)

    parsed = manager._parse_credentials_from_text("0123456789abcdef0123456789abcdef")
    assert parsed == [{"username": "harvested_user_1", "password": "0123456789abcdef0123456789abcdef"}]

    manager.validator_completed("ssti_validator")
    assert any(call[0] == "add_confirmed_vulnerability" and call[1]["vuln_id"] == "rce_confirmed" for call in store.calls)
