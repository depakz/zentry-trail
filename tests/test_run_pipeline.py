import asyncio
from types import SimpleNamespace

import modules.pipeline.brain.dag_engine_enhanced as dge


def test_run_pipeline_basic(monkeypatch):
    # Fast deterministic executor functions
    monkeypatch.setattr(dge, "test_xss", lambda endpoint: {"success": False})
    monkeypatch.setattr(dge, "run_sqlmap", lambda endpoint: {"success": False})
    monkeypatch.setattr(dge, "run_git_extractor", lambda base: {"success": False})
    monkeypatch.setattr(dge, "run_ssh_brute", lambda host, port, **kwargs: {"success": False})
    monkeypatch.setattr(dge, "run_config_reader", lambda url: {"success": False})

    brain = dge.DAGBrain(use_graph_engine=True)
    state = {"url": "https://example.test", "findings": []}
    engine = dge.ConcurrentValidationEngine(dag_brain=brain, state=state, max_workers=2)

    # Run the pipeline in an event loop
    result = asyncio.run(engine.run_pipeline(progress={}))

    assert isinstance(result, dict)
    assert "results" in result and "snapshot" in result and "scheduler_metrics" in result
    metrics = result["scheduler_metrics"]
    assert isinstance(metrics.get("queued_batches", 0), (int,))
    assert isinstance(metrics.get("executed_batches", 0), (int,))
