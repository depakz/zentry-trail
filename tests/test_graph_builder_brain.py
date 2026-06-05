from types import SimpleNamespace

import pytest

from modules.pipeline.brain.graph_builder import DAGGraph, DAGNode, GraphBuilder, GraphEngine, GraphEngineAdapter
from modules.pipeline.brain.kb import ValidatorSpec


def test_graph_builder_builds_context_and_vulnerability_nodes():
    specs = [
        ValidatorSpec(
            id="match",
            name="MatchValidator",
            class_path="fake.match",
            description="match",
            priority=20,
            keywords=["git"],
            required_ports=[80],
            required_protocols=["http"],
        ),
        ValidatorSpec(
            id="miss",
            name="MissValidator",
            class_path="fake.miss",
            description="miss",
            priority=5,
            keywords=["ssh"],
            required_ports=[22],
            required_protocols=["https"],
        ),
    ]

    state = {
        "target": " example.com ",
        "ports": [80, "81", "skip"],
        "protocols": ["HTTP"],
        "findings": [{"title": "Exposed .git directory"}],
    }

    graph = GraphBuilder().build(state, specs)

    assert "target:example.com" in graph.nodes
    assert "port:80" in graph.nodes
    assert "protocol:http" in graph.nodes
    assert graph.nodes["validator:match"].data["matched_context"] is True
    assert graph.nodes["validator:miss"].data["matched_context"] is False
    assert ("target:example.com", "validator:match") in graph.edges
    assert ("target:example.com", "vulnerability:redis-no-auth") in graph.edges


def test_topological_sort_prefers_higher_priority_and_detects_cycles():
    graph = DAGGraph()
    graph.add_node(
        DAGNode(
            id="validator:high",
            kind="validator",
            label="High",
            data={"spec": ValidatorSpec(id="high", name="High", class_path="fake.high", description="", priority=90)},
        )
    )
    graph.add_node(
        DAGNode(
            id="validator:low",
            kind="validator",
            label="Low",
            data={"spec": ValidatorSpec(id="low", name="Low", class_path="fake.low", description="", priority=10)},
        )
    )

    ordered = GraphBuilder().topological_sort(graph)
    assert ordered.index("validator:high") < ordered.index("validator:low")

    cycle = DAGGraph()
    cycle.add_node(DAGNode(id="a", kind="validator", label="A"))
    cycle.add_node(DAGNode(id="b", kind="validator", label="B"))
    cycle.add_edge("a", "b")
    cycle.add_edge("b", "a")

    with pytest.raises(ValueError, match="cycle"):
        GraphBuilder().topological_sort(cycle)


def test_graph_engine_methods_and_adapter_runtime():
    engine = GraphEngine()
    engine.add_state_node("source", kind="state", label="Source", active=True)
    engine.add_state_node("inactive", kind="state", label="Inactive", active=False)
    engine.add_state_node("target", kind="state", label="Target", active=True)
    engine.add_action_edge("source", "target", "edge-1", "run", {"keep": "value"})
    engine.add_action_edge("inactive", "target", "edge-2", "run", {})

    ready = engine.get_ready_edges()
    assert [(u, v, edge.id) for u, v, edge in ready] == [("source", "target", "edge-1")]

    engine.inject_loot_into_downstream("source", {"keep": "override", "new": "loot"})
    engine.mark_edge_executed("source", "target", {"ok": True})

    snapshot = engine.get_graph_snapshot()
    assert snapshot["nodes"][0]["kind"] == "state"
    assert snapshot["edges"][0]["executed"] is True
    assert snapshot["edges"][0]["params"]["keep"] == "value"
    assert snapshot["edges"][0]["params"]["new"] == "loot"

    adapter = GraphEngineAdapter()
    dag = adapter.build(
        {"target": "https://example.test", "findings": [{"title": "Exposed .git directory"}]},
        [ValidatorSpec(id="one", name="One", class_path="fake.one", description="")],
    )

    assert isinstance(dag, DAGGraph)
    assert adapter.engine is not None
    assert any(node_id.startswith("action:git_directory_found") for node_id in adapter.engine.graph.nodes)
