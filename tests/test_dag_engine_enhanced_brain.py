from types import SimpleNamespace

import asyncio

from modules.pipeline.brain import dag_engine_enhanced as deh
from modules.pipeline.brain.kb import get_default_validator_specs


class FakeValidator:
    def __init__(self, context=None):
        self.context = context
        self.execution_context = None
        self.validator_id = None
        self.priority = None

    def can_run(self, state):
        return True


class FakeFactStore:
    def get_summary(self):
        return {"facts": 1}

    def export(self):
        return {"facts": ["one"]}


class FakeEndpointNormalizer:
    def __init__(self):
        self.skipped = set()

    def should_skip_scan(self, endpoint, vulnerability_type=None):
        return endpoint in self.skipped or f"pattern:{endpoint}" in self.skipped

    def register_endpoint(self, endpoint, vulnerability_type=None):
        return f"pattern:{endpoint}", {"endpoint": endpoint, "vulnerability_type": vulnerability_type}

    def mark_pattern_scanned(self, pattern_key):
        self.skipped.add(pattern_key)

    def get_pattern_stats(self):
        return {"skipped": len(self.skipped)}

    def export(self):
        return {"skipped": sorted(self.skipped)}


class FakeAttackChainManager:
    def __init__(self, fact_store):
        self.fact_store = fact_store
        self.callbacks = []
        self.completed = []

    def register_chain_callback(self, callback):
        self.callbacks.append(callback)

    def validator_completed(self, parent_validator_id):
        self.completed.append(parent_validator_id)

    def get_pending_exploitation_nodes(self):
        return [SimpleNamespace(id="loot-1")]

    def get_active_chains(self):
        return [{"id": "chain-1"}]

    def get_chain_statistics(self):
        return {"completed": len(self.completed)}


class FakeResultProcessor:
    def __init__(self, fact_store, endpoint_normalizer, attack_chain_manager):
        self.fact_store = fact_store

    def process_result(self, item):
        return item


class FakeRuntime:
    def __init__(self):
        self.loot = []
        self.executed = []

    def inject_loot_into_downstream(self, node_id, loot):
        self.loot.append((node_id, dict(loot)))

    def mark_edge_executed(self, u, v, result=None):
        self.executed.append((u, v, result or {}))

    def get_graph_snapshot(self):
        return {"nodes": [], "edges": []}


class FakeValidatorModule:
    class FakeValidator:
        def __init__(self, context=None):
            self.context = context

        def can_run(self, state):
            return True

        def run(self, state):
            return {"success": True, "evidence": {"extra": {"loot": "found"}}, "vulnerability": "fake"}


def _validator_map():
    return {spec.class_path: FakeValidator for spec in get_default_validator_specs()}


def test_enhanced_planner_and_state_helpers(monkeypatch):
    monkeypatch.setattr(deh, "FactStore", FakeFactStore)
    monkeypatch.setattr(deh, "EndpointNormalizer", FakeEndpointNormalizer)
    monkeypatch.setattr(deh, "AttackChainManager", FakeAttackChainManager)
    monkeypatch.setattr(deh, "VALIDATOR_CLASS_MAP", _validator_map())

    brain = deh.DAGBrain(use_graph_engine=False)
    state = {"target": "http://example.test", "url": "http://example.test", "protocols": ["http"], "ports": [6379]}

    plan = brain.plan_validations(state)
    assert plan.validators
    assert plan.fact_store is brain.fact_store
    assert plan.endpoint_normalizer is brain.endpoint_normalizer
    assert plan.attack_chain_manager is brain.attack_chain_manager

    selected = brain.build_plan(state, selected_validators=["override"])
    assert selected.validators == ["override"]

    callback_calls = []
    brain.register_chain_injection_callback(lambda node: callback_calls.append(node.id))
    assert brain.attack_chain_manager.callbacks
    pending = brain.inject_exploitation_nodes("validator:one")
    assert pending[0].id == "loot-1"
    assert brain.attack_chain_manager.completed == ["validator:one"]

    assert brain.should_skip_endpoint("https://example.test/path") is False
    brain.mark_endpoint_pattern_scanned("https://example.test/path")
    assert brain.should_skip_endpoint("https://example.test/path") is True

    monkeypatch.setattr(brain.cve_mapper, "map_findings_to_cves", lambda findings: {"CVE-2025-46817": ["redis_no_auth"]})
    monkeypatch.setattr(brain.cve_mapper, "get_cve_verdict_data", lambda cve_id: {"cve_id": cve_id, "title": "Redis CVE", "description": "", "severity": "critical"})
    cve_plan = brain.plan_cve_validations(state, [{"cve": "CVE-2025-46817"}])
    assert cve_plan.cve_to_validators == {"CVE-2025-46817": ["redis_no_auth"]}
    assert cve_plan.validator_instances

    description = brain.describe(state)
    assert description["validators"]
    assert description["fact_store_summary"] == {"facts": 1}
    assert description["endpoint_deduplication_stats"] == {"skipped": 1}

    engine_state = brain.get_engine_state()
    assert engine_state["fact_store"] == {"facts": ["one"]}
    assert engine_state["active_chains"] == [{"id": "chain-1"}]
    assert brain.create_concurrent_engine(state, max_workers=4).max_workers == 4


def test_concurrent_engine_helpers_and_execution(monkeypatch):
    monkeypatch.setattr(deh, "FactStore", FakeFactStore)
    monkeypatch.setattr(deh, "EndpointNormalizer", FakeEndpointNormalizer)
    monkeypatch.setattr(deh, "AttackChainManager", FakeAttackChainManager)
    monkeypatch.setattr(deh, "ValidationResultProcessor", FakeResultProcessor)
    monkeypatch.setattr(deh, "VALIDATOR_CLASS_MAP", {"fake.validator": FakeValidator})
    monkeypatch.setattr(deh.importlib, "import_module", lambda module_path: SimpleNamespace(FakeValidator=FakeValidatorModule.FakeValidator))
    monkeypatch.setattr(deh, "run_sqlmap", lambda endpoint: {"success": True, "evidence": {"value": 1}})

    brain = deh.DAGBrain(validator_specs=[deh.ValidatorSpec(id="fake-validator", name="Fake", class_path="fake.validator", description="")], use_graph_engine=False)
    engine = deh.ConcurrentValidationEngine(brain, state={"url": "https://Example.test:8443/path", "validation_targets": ["https://one.test", "ftp://skip", "https://two.test"]}, max_workers=2)

    assert engine._normalize_target_key("https://Example.test:8443/path", engine.state) == "example.test:8443"
    assert engine._edge_batch_key("u", "v", SimpleNamespace(action="run_validator", params={"validator_id": "fake-validator"}), engine.state).startswith("example.test:8443|run_validator|fake-validator")
    assert "fake-validator" in engine._dedupe_key("u", "v", SimpleNamespace(action="run_validator", params={"validator_id": "fake-validator"}), "batch")
    assert engine._candidate_validation_urls(engine.state) == ["https://one.test", "https://two.test"]

    metrics = engine._finalize_metrics(25.0)
    assert metrics["max_workers"] == 2
    assert metrics["total_duration_ms"] == 25.0

    runtime = FakeRuntime()
    spec_map = {"fake-validator": deh.ValidatorSpec(id="fake-validator", name="Fake", class_path="fake.module.FakeValidator", description="")}
    run_result = engine._execute_edge_sync(
        "root",
        "validator",
        SimpleNamespace(action="run_validator", params={"validator_id": "fake-validator"}),
        engine.state,
        spec_map,
        runtime,
    )
    assert run_result["result"]["success"] is True
    assert runtime.loot and runtime.loot[0][1]["loot"] == "found"

    sqlmap_result = engine._execute_edge_sync(
        "root",
        "sql",
        SimpleNamespace(action="sqlmap", params={}),
        engine.state,
        spec_map,
        runtime,
    )
    assert sqlmap_result["result"]["success"] is True

    idle = asyncio.run(engine.run_pipeline(progress={}))
    assert idle["results"] == []
