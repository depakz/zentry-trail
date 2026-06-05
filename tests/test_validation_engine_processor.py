from types import SimpleNamespace

import modules.pipeline.engine.validation_engine_enhanced as ve
from modules.pipeline.brain.fact_store import FactStore


def test_extract_service_info_and_fact_store_integration():
    fs = FactStore()
    proc = ve.ValidationResultProcessor(fact_store=fs)

    result = {
        "success": True,
        "validator_id": "svc1",
        "vulnerability": "service_discovery",
        "evidence": {"response": {"server": "nginx", "version": "1.18"}},
        "validation": {"confidence_score": 0.85},
        "target": "https://example.test",
    }

    out = proc.process_result(result)
    assert isinstance(out, dict)
    assert "extracted_facts" in out
    assert isinstance(out["extracted_facts"], list)
    # Fact store should include the service info
    export = fs.export()
    svc = export.get("service_info", {}) or {}
    assert any("nginx" in k for k in svc.keys())


def test_juice_shop_signature_triggers(monkeypatch):
    # Force signature checker to return True
    monkeypatch.setattr(ve, "check_juice_shop_error", lambda b: True)

    fs = FactStore()
    proc = ve.ValidationResultProcessor(fact_store=fs)

    result = {
        "error": "stacktrace here",
        "evidence": {"response": {}},
    }

    out = proc.process_result(result)
    assert out.get("success") is True
    assert out.get("severity") == "high"
    assert out.get("vulnerability") == "juice-shop-stacktrace-disclosure"
    assert out.get("trigger") == "juice_shop_stacktrace"


def test_state_manager_update_counts_and_signals():
    fs = FactStore()
    sm = ve.StateManager(fact_store=fs)
    state = {}
    results = [
        {"validator_id": "v1", "vulnerability": "x", "success": True},
        {"validator_id": "v2", "vulnerability": "y", "success": False},
    ]

    new_confirmed = sm.update(state, results)
    assert new_confirmed == 1
    assert isinstance(state.get("confirmed_vulns"), list)
    assert "x" in state.get("signals", [])
    assert "fact_store_state" in state
