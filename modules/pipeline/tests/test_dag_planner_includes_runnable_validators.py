from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.pipeline.brain.dag_engine_enhanced import DAGBrain


def test_plan_validations_includes_runnable_http_validators() -> None:
    brain = DAGBrain(use_graph_engine=True)
    state = {"target": "http://example.test", "url": "http://example.test", "protocols": ["http"]}

    plan = brain.plan_validations(state)
    validator_names = {validator.__class__.__name__ for validator in plan.validators}

    assert "InsecureDeserializationValidator" in validator_names
    assert "LoggingValidator" in validator_names
    assert "SSRFValidator" in validator_names
    assert "MissingSecurityHeadersValidator" in validator_names


def test_build_graph_includes_all_validator_nodes_for_http_targets() -> None:
    brain = DAGBrain(use_graph_engine=True)
    state = {"target": "http://example.test", "url": "http://example.test", "protocols": ["http"]}

    graph = brain.build_graph(state)
    validator_ids = {
        node.data.get("spec").id
        for node in graph.nodes.values()
        if node.kind == "validator" and node.data.get("spec") is not None
    }

    assert "broken_access_control_validator" in validator_ids
    assert "insecure_design_validator" in validator_ids