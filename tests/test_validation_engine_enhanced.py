from types import SimpleNamespace

from modules.pipeline.engine import validation_engine_enhanced as vee


class FakeFact:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def to_dict(self):
        return {"key": self.key, "value": self.value}


class FakeFactStore:
    def __init__(self):
        self.calls = []

    def add_credential(self, **kwargs):
        self.calls.append(("add_credential", kwargs))
        return FakeFact(kwargs["username"], kwargs["password"])

    def add_confirmed_vulnerability(self, **kwargs):
        self.calls.append(("add_confirmed_vulnerability", kwargs))
        return FakeFact(kwargs["vuln_id"], kwargs["vuln_type"])

    def add_fact(self, fact):
        self.calls.append(("add_fact", fact))
        return fact

    def add_internal_host(self, **kwargs):
        self.calls.append(("add_internal_host", kwargs))
        return FakeFact(kwargs["hostname"], kwargs["confidence"])

    def add_exploitation_artifact(self, **kwargs):
        self.calls.append(("add_exploitation_artifact", kwargs))
        return FakeFact(kwargs["artifact_id"], kwargs["artifact_type"])

    def export(self):
        return {"calls": len(self.calls)}


class FakeEndpointNormalizer:
    def __init__(self):
        self.calls = []

    def should_skip_scan(self, endpoint, vulnerability_type=None):
        self.calls.append((endpoint, vulnerability_type))
        return False


class FakeChainManager:
    def __init__(self, fact_store):
        self.fact_store = fact_store
        self.completed = []

    def validator_completed(self, validator_id):
        self.completed.append(validator_id)

    def get_pending_exploitation_nodes(self):
        return [SimpleNamespace(to_dict=lambda: {"id": "node-1"})]


class FakeProofCollector:
    def attach(self, result):
        result = dict(result)
        result["proof_attached"] = True
        return result


class FakeValidator:
    priority = 50
    validator_id = "fake-validator"

    def __init__(self, result):
        self._result = result
        self.context = None
        self.execution_context = None

    def can_run(self, state):
        return True

    def run(self, state):
        return self._result


def test_processor_helpers_and_fact_extraction(monkeypatch):
    monkeypatch.setattr(vee, "ProofCollector", FakeProofCollector)

    store = FakeFactStore()
    chain = FakeChainManager(store)
    processor = vee.ValidationResultProcessor(store, FakeEndpointNormalizer(), chain)

    assert vee._is_confirmed({"success": True}) is True
    assert vee._confirmed_key({"validator_id": "v1", "vulnerability": "x"}) == ("v1", "x")
    assert vee._juice_shop_signature_trigger({"evidence": "SQLITE_ERROR: near 'foo': syntax error"}) is True

    result = {
        "success": True,
        "validator_id": "v1",
        "vulnerability": "credential_leak",
        "target": "example.test",
        "validation": {"status": "confirmed", "confidence_score": 0.9},
        "evidence": {"response": {"username": "alice", "password": "secret"}},
    }

    processed = processor.process_result(result)
    assert processed["proof_attached"] is True
    assert processed["injected_nodes"] == [{"id": "node-1"}]
    assert processed["extracted_facts"]
    assert any(name == "add_confirmed_vulnerability" for name, _ in store.calls)
    assert any(name == "add_credential" for name, _ in store.calls)

    triggered = processor.process_result({"evidence": "SQLITE_ERROR: near 'foo': syntax error"})
    assert triggered["success"] is True
    assert triggered["validation"]["status"] == "confirmed"


def test_validation_engine_and_state_manager(monkeypatch):
    monkeypatch.setattr(vee, "FactStore", FakeFactStore)
    monkeypatch.setattr(vee, "EndpointNormalizer", FakeEndpointNormalizer)
    monkeypatch.setattr(vee, "AttackChainManager", FakeChainManager)
    monkeypatch.setattr(vee, "ProofCollector", FakeProofCollector)

    engine = vee.ValidationEngine()
    engine.register(FakeValidator({
        "success": True,
        "validator_id": "fake-validator",
        "vulnerability": "credential_leak",
        "target": "example.test",
        "validation": {"status": "confirmed", "confidence_score": 0.9},
        "evidence": {"response": {"username": "bob", "password": "pw"}},
    }))

    findings = engine.run({"target": "example.test"})
    assert findings and findings[0]["success"] is True
    assert findings[0]["injected_nodes"] == [{"id": "node-1"}]
    assert sum(1 for name, _ in engine.fact_store.calls if name == "add_confirmed_vulnerability") == 1

    plan = SimpleNamespace(
        validators=[FakeValidator({"success": True, "validator_id": "fake-validator", "vulnerability": "credential_leak", "target": "example.test", "validation": {"status": "confirmed", "confidence_score": 0.9}, "evidence": {"response": {"username": "carol", "password": "pw2"}}})],
        fact_store=FakeFactStore(),
        endpoint_normalizer=FakeEndpointNormalizer(),
        attack_chain_manager=FakeChainManager(FakeFactStore()),
    )

    plan_results = engine.run(plan, {"target": "example.test"})
    assert plan_results and plan_results[0]["validator_id"] == "fake-validator"

    state_manager = vee.StateManager(FakeFactStore())
    state = {}
    new_confirmed = state_manager.update(
        state,
        [
            {"success": True, "validator_id": "fake-validator", "vulnerability": "credential_leak", "validation": {"status": "confirmed", "confidence_score": 0.9}},
            {"success": False, "validator_id": "other", "vulnerability": "ignored"},
        ],
    )
    assert new_confirmed == 1
    assert state["validation_results"]
    assert state["confirmed_vulns"]
    assert state["signals"] == ["credential_leak"]
    assert state["fact_store_state"] == {"calls": 0}
