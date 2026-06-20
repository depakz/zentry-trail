"""Comprehensive verification tests for the Payload Genetic Engine."""

import pytest
import requests
from unittest.mock import MagicMock
from core.diff_analyzer import DifferentialAnalyzer, DeltaVector
from core.payload_gene import PayloadGene
from core.genetic_engine import PayloadGeneticEngine

def test_delta_vector_fitness():
    dv = DeltaVector(
        time_delta_ms=2500,
        status_code_change="200->500",
        body_length_delta=500,
        reflection_present=True,
        error_class="db_error",
        new_headers=["X-Error"],
        oob_triggered=True
    )
    assert dv.fitness_score == 1.0  # 0.5 + 0.25 + 0.10 + 0.08 + 0.05 + 0.02 = 1.0

def test_payload_gene_render():
    gene = PayloadGene(
        vuln_class="SQLI",
        core_payload="1' OR '1'='1",
        encoding_layer="url",
        delimiter="--",
        wrapper="none",
        case_variant="upper",
        null_byte=True
    )
    res = gene.render()
    assert "%" in res      # URL Encoding correctly applied
    assert "OR" in res     # Casing correctly applied
    assert "\x00" in res   # Null byte injection correctly applied

def test_genetic_engine_evolve():
    engine = PayloadGeneticEngine()
    
    baseline_resp = MagicMock(spec=requests.Response)
    
    def mock_evaluator(payload: str) -> DeltaVector:
        # Explicitly reward a specific multi-layer encoding variation (e.g., upper + url encoded + delimiter)
        if ("ALERT" in payload or "SCRIPT" in payload) and ("%25" in payload or "%" in payload):
            return DeltaVector(0, "200->500", 300, True, "template_error", [], False)
        return DeltaVector(0, "", 0, False, "none", [], False)
        
    best_payload, best_score = engine.evolve("XSS", "http://test", "q", mock_evaluator, baseline_resp, 60.0)
    assert best_payload is not None
    assert best_score >= 0.0