import asyncio

import modules.pipeline.brain.dag_engine_enhanced as dge


class FakeEdge:
    def __init__(self, id, action, params=None):
        self.id = id
        self.action = action
        self.params = params or {}


class FakeRuntime:
    def __init__(self, edges):
        self._edges = edges
        self._first = True

    def get_ready_edges(self):
        if self._first:
            self._first = False
            return list(self._edges)
        return []

    def get_graph_snapshot(self):
        return {"nodes": [], "edges": []}

    def inject_loot_into_downstream(self, v, loot):
        pass

    def mark_edge_executed(self, u, v, result=None):
        pass


def test_run_pipeline_multiple_batches(monkeypatch):
    # Patch executor functions to be deterministic
    monkeypatch.setattr(dge, "test_xss", lambda endpoint: {"success": True})
    monkeypatch.setattr(dge, "run_sqlmap", lambda endpoint: {"success": True})
    monkeypatch.setattr(dge, "run_git_extractor", lambda base: {"success": True})
    monkeypatch.setattr(dge, "run_config_reader", lambda url: {"success": True})

    brain = dge.DAGBrain(use_graph_engine=True)
    state = {"url": "https://example.test"}
    engine = dge.ConcurrentValidationEngine(dag_brain=brain, state=state, max_workers=2)

    # Four edges with different actions -> distinct batch keys
    edges = [
        ("a1", "b1", FakeEdge("e1", "xss", {"endpoint": "https://a.test"})),
        ("a2", "b2", FakeEdge("e2", "sqlmap", {"endpoint": "https://b.test"})),
        ("a3", "b3", FakeEdge("e3", "git_extractor", {"url": "https://c.test"})),
        ("a4", "b4", FakeEdge("e4", "config_reader", {"url": "https://d.test"})),
    ]

    runtime = FakeRuntime(edges=edges)

    def fake_build_graph(s):
        brain.graph_builder.engine = runtime

    brain.build_graph = fake_build_graph

    res = asyncio.run(engine.run_pipeline(progress={}))
    metrics = res.get("scheduler_metrics") or {}

    assert metrics.get("queued_batches", 0) == 4
    assert metrics.get("queued_edges", 0) == 4
    assert metrics.get("executed_batches", 0) == 4
    assert metrics.get("executed_edges", 0) == 4
