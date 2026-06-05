from types import SimpleNamespace

import modules.pipeline.brain.dag_engine_enhanced as dge


def make_engine():
    brain = dge.DAGBrain(use_graph_engine=True)
    engine = dge.ConcurrentValidationEngine(dag_brain=brain, state={"url": "https://example.test"}, max_workers=2)
    return engine


def test_normalize_and_batch_keys():
    engine = make_engine()
    # normalize host with scheme
    key = engine._normalize_target_key("https://example.test/path", {})
    assert key.startswith("example.test")

    # edge batch key and dedupe key
    edge = SimpleNamespace(action="run_validator", params={"validator_id": "v1", "url": "https://example.test"})
    batch_key = engine._edge_batch_key("u", "v", edge, {"url": "https://example.test"})
    assert "example.test" in batch_key and "v1" in batch_key
    dedupe = engine._dedupe_key("u", "v", edge, batch_key)
    assert batch_key in dedupe and "u" in dedupe and "v" in dedupe


def test_execute_edge_actions_monkeypatched(monkeypatch):
    engine = make_engine()

    # Fake runtime to capture injections and marks
    calls = []

    class FakeRuntime:
        def inject_loot_into_downstream(self, v, loot):
            calls.append(("inject", v, loot))

        def mark_edge_executed(self, u, v, result=None):
            calls.append(("mark", u, v, result))

        def get_graph_snapshot(self):
            return {"nodes": [], "edges": []}

        def get_ready_edges(self):
            return []

    runtime = FakeRuntime()

    # Monkeypatch executor functions in module namespace
    monkeypatch.setattr(dge, "test_xss", lambda endpoint: {"success": True, "evidence": {"matched": "xss", "extra": {"x": "y"}}})
    monkeypatch.setattr(dge, "run_sqlmap", lambda endpoint: {"success": True, "evidence": {"matched": "sql_injection"}})
    monkeypatch.setattr(dge, "run_git_extractor", lambda base: {"success": True, "evidence": {"paths": ["/src"], "credentials": ["u:p"]}})
    monkeypatch.setattr(dge, "run_ssh_brute", lambda host, port, **kwargs: {"success": True, "evidence": {"banner": "SSH-2.0"}})
    monkeypatch.setattr(dge, "run_config_reader", lambda url: {"success": True, "evidence": {"matched_indicators": ["SECRET=1"]}})

    state = {"url": "https://example.test"}

    # xss action
    edge = SimpleNamespace(action="xss", params={})
    res = engine._execute_edge_sync("u", "v", edge, state, {}, runtime)
    assert res["result"]["success"] is True
    # xss action does not inject via this code path

    calls.clear()
    # sqlmap action
    edge = SimpleNamespace(action="sqlmap", params={"endpoint": "https://example.test"})
    res = engine._execute_edge_sync("u2", "v2", edge, state, {}, runtime)
    assert res["result"]["success"] is True
    # sqlmap does not inject loot here

    calls.clear()
    # git_extractor action
    edge = SimpleNamespace(action="git_extractor", params={"url": "https://example.test"})
    res = engine._execute_edge_sync("u3", "v3", edge, state, {}, runtime)
    assert res["result"]["success"] is True
    assert any(c[0] == "inject" for c in calls)

    calls.clear()
    # ssh_brute action
    edge = SimpleNamespace(action="ssh_brute", params={"host": "example.test", "port": 22})
    res = engine._execute_edge_sync("u4", "v4", edge, state, {}, runtime)
    assert res["result"]["success"] is True

    calls.clear()
    # config_reader action
    edge = SimpleNamespace(action="config_reader", params={"url": "https://example.test"})
    res = engine._execute_edge_sync("u5", "v5", edge, state, {}, runtime)
    assert res["result"]["success"] is True
