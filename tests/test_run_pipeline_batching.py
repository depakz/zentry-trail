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
        self.injected = []
        self.marked = []

    def get_ready_edges(self):
        if self._first:
            self._first = False
            return list(self._edges)
        return []

    def get_graph_snapshot(self):
        return {"nodes": [], "edges": []}

    def inject_loot_into_downstream(self, v, loot):
        self.injected.append((v, loot))

    def mark_edge_executed(self, u, v, result=None):
        self.marked.append((u, v, result))


def test_run_pipeline_batching_and_dedupe(monkeypatch):
    # Fast deterministic xss function
    monkeypatch.setattr(dge, "test_xss", lambda endpoint: {"success": True, "evidence": {"matched": endpoint}})

    brain = dge.DAGBrain(use_graph_engine=True)
    state = {"url": "https://example.test"}
    engine = dge.ConcurrentValidationEngine(dag_brain=brain, state=state, max_workers=2)

    # Create two edges that share the same batch key (same target + action)
    e1 = FakeEdge(id="e1", action="xss", params={"endpoint": "https://example.test"})
    e2 = FakeEdge(id="e2", action="xss", params={"endpoint": "https://example.test"})

    u1, v1 = "n1", "n2"
    u2, v2 = "n3", "n4"

    # Compute keys and pre-populate execution cache to force a dedupe skip for e2
    batch_key_e2 = engine._edge_batch_key(u2, v2, e2, state)
    dedupe_key_e2 = engine._dedupe_key(u2, v2, e2, batch_key_e2)
    engine._execution_cache.add(dedupe_key_e2)

    # Attach fake runtime to brain via build_graph
    runtime = FakeRuntime(edges=[(u1, v1, e1), (u2, v2, e2)])

    def fake_build_graph(s):
        brain.graph_builder.engine = runtime

    brain.build_graph = fake_build_graph

    # Run pipeline
    res = asyncio.run(engine.run_pipeline(progress={}))

    assert isinstance(res, dict)
    metrics = res.get("scheduler_metrics") or {}
    # One batch should be queued (both edges would be batched, but e2 is deduped before queuing)
    assert metrics.get("queued_batches", 0) == 1
    # Only one edge actually queued because e2 was deduped
    assert metrics.get("queued_edges", 0) == 1
    assert metrics.get("dedupe_skips", 0) >= 1
    # One executed edge (e1)
    assert metrics.get("executed_edges", 0) == 1
    assert metrics.get("executed_batches", 0) == 1
