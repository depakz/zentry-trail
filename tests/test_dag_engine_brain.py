from types import SimpleNamespace

import pytest

from modules.pipeline.brain import dag_engine as de
from modules.pipeline.brain.dag_engine import DAGBrain, DAGGraph
from modules.pipeline.brain.graph_builder import DAGNode
from modules.pipeline.brain.kb import ValidatorSpec
from modules.pipeline.engine.models import ExecutionContext


class ContextAwareValidator:
    def __init__(self, context=None):
        self.context = context
        self.execution_context = None
        self.validator_id = None
        self.priority = None

    def can_run(self, state):
        return True


class NoContextValidator:
    def __init__(self):
        self.context = None
        self.execution_context = None
        self.validator_id = None
        self.priority = None

    def can_run(self, state):
        return True


class FalseValidator:
    def __init__(self, context=None):
        self.context = context
        self.execution_context = None

    def can_run(self, state):
        return False


def _fake_class_map():
    return {
        "fake.selected": ContextAwareValidator,
        "fake.fallback": FalseValidator,
        "fake.redis": ContextAwareValidator,
    }


def test_instantiate_validator_and_execution_layers():
    brain = DAGBrain(validator_specs=[ValidatorSpec(id="base", name="Base", class_path="fake.base", description="")])
    context = ExecutionContext.from_state({"target": "example.test"})

    instance = brain._instantiate_validator(NoContextValidator, spec=ValidatorSpec(id="x", name="X", class_path="fake.x", description="", priority=7), context=context)
    assert instance.context == context
    assert instance.execution_context == context
    assert instance.validator_id == "x"
    assert instance.priority == 7

    graph = DAGGraph()
    graph.add_node(DAGNode(id="root", kind="root", label="root"))
    graph.add_node(DAGNode(id="a", kind="validator", label="A", data={"spec": ValidatorSpec(id="a", name="A", class_path="fake.a", description="", priority=5)}))
    graph.add_node(DAGNode(id="b", kind="validator", label="B", data={"spec": ValidatorSpec(id="b", name="B", class_path="fake.b", description="", priority=1)}))
    graph.add_node(DAGNode(id="c", kind="validator", label="C", data={"spec": ValidatorSpec(id="c", name="C", class_path="fake.c", description="", priority=0)}))
    graph.add_edge("root", "a")
    graph.add_edge("root", "b")
    graph.add_edge("a", "c")

    layers = brain.get_execution_layers(graph)
    assert layers[0] == ["root"]
    assert set(layers[1]) == {"a", "b"}
    assert layers[2] == ["c"]


def test_plan_validations_and_cve_validations(monkeypatch):
    selected_spec = ValidatorSpec(
        id="selected",
        name="Selected",
        class_path="fake.selected",
        description="",
        priority=50,
        required_protocols=["http"],
    )
    fallback_spec = ValidatorSpec(
        id="fallback",
        name="Fallback",
        class_path="fake.fallback",
        description="",
        priority=10,
    )
    redis_spec = ValidatorSpec(
        id="redis_no_auth",
        name="Redis",
        class_path="fake.redis",
        description="",
        priority=100,
        required_ports=[6379],
    )

    monkeypatch.setattr(de, "_get_validator_class_map", _fake_class_map)

    brain = DAGBrain(validator_specs=[selected_spec, fallback_spec, redis_spec])

    plan_graph = DAGGraph()
    plan_graph.add_node(DAGNode(id="root", kind="root", label="root"))
    plan_graph.add_node(DAGNode(id="validator:selected", kind="validator", label="Selected", data={"spec": selected_spec}))
    plan_graph.add_node(DAGNode(id="validator:redis_no_auth", kind="validator", label="Redis", data={"spec": redis_spec}))
    plan_graph.add_edge("root", "validator:selected")
    plan_graph.add_edge("root", "validator:redis_no_auth")

    monkeypatch.setattr(brain, "build_graph", lambda state: plan_graph)
    monkeypatch.setattr(brain.graph_builder, "topological_sort", lambda graph: ["root", "validator:selected", "validator:redis_no_auth"])

    plan = brain.plan_validations({"target": "example.test", "protocols": ["http"]})
    assert [validator.__class__.__name__ for validator in plan.validators] == ["ContextAwareValidator", "ContextAwareValidator"]
    assert plan.validators[0].validator_id == "selected"
    assert plan.validators[0].priority == 50
    assert plan.execution_layers[0] == ["root"]

    cve_graph = DAGGraph()
    cve_graph.add_node(DAGNode(id="root", kind="root", label="root"))
    cve_graph.add_node(DAGNode(id="validator:redis_no_auth", kind="validator", label="Redis", data={"spec": redis_spec}))
    cve_graph.add_edge("root", "validator:redis_no_auth")

    monkeypatch.setattr(brain, "build_graph", lambda state: cve_graph)
    monkeypatch.setattr(brain.graph_builder, "topological_sort", lambda graph: ["root", "validator:redis_no_auth"])
    monkeypatch.setattr(brain.cve_mapper, "map_findings_to_cves", lambda findings: {"CVE-2025-46817": ["redis_no_auth"]})
    monkeypatch.setattr(brain.cve_mapper, "get_cve_verdict_data", lambda cve_id: {"cve_id": cve_id, "title": "Redis CVE", "description": "", "severity": "critical"})

    cve_plan = brain.plan_cve_validations({"target": "redis.example", "ports": [6379]}, [{"cve": "CVE-2025-46817"}])
    assert cve_plan.cve_to_validators == {"CVE-2025-46817": ["redis_no_auth"]}
    assert cve_plan.cve_details["CVE-2025-46817"]["title"] == "Redis CVE"
    assert "redis_no_auth" in cve_plan.validator_instances
    assert cve_plan.context_validator_ids == ["redis_no_auth"]


def test_describe_uses_planned_graph(monkeypatch):
    selected_spec = ValidatorSpec(id="selected", name="Selected", class_path="fake.selected", description="", priority=50)
    monkeypatch.setattr(de, "_get_validator_class_map", _fake_class_map)
    brain = DAGBrain(validator_specs=[selected_spec])

    graph = DAGGraph()
    graph.add_node(DAGNode(id="root", kind="root", label="root"))
    graph.add_node(DAGNode(id="validator:selected", kind="validator", label="Selected", data={"spec": selected_spec}))
    graph.add_edge("root", "validator:selected")
    context = brain.plan_validations({"target": "example.test"}).context

    monkeypatch.setattr(brain, "plan_validations", lambda state: SimpleNamespace(graph=graph, ordered_nodes=["root", "validator:selected"], validators=[ContextAwareValidator(context=context)], context=context))

    description = brain.describe({"target": "example.test"})
    assert description["validators"] == ["ContextAwareValidator"]
    assert description["ordered_nodes"] == ["root", "validator:selected"]
