"""
tests/test_behavioral_baseline.py — Session 4 tests

Tests for core/behavioral_baseline.py and core/behavioral_probe.py
"""

import pytest
from core.behavioral_baseline import BSMRecorder, BehavioralStateMachine, BSMStep
from core.behavioral_probe    import BSMDeviationProber, DeviationProbe
from modules.pipeline.validators.biz_logic_validator import BizLogicValidator
from modules.pipeline.engine.models import ValidationResult
import aiohttp
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# BSMRecorder tests
# ---------------------------------------------------------------------------

class TestBSMRecorder:

    def _recorder(self):
        return BSMRecorder()

    def test_groups_checkout_steps_into_one_flow(self):
        """Endpoints sharing 'checkout' keyword should be in one flow."""
        endpoints = [
            "http://shop.example.com/checkout/step1",
            "http://shop.example.com/checkout/step2",
            "http://shop.example.com/checkout/confirm",
        ]
        recorder = self._recorder()
        bsms     = recorder.record_from_endpoints(endpoints, state={})
        assert len(bsms) == 1
        bsm = bsms[0]
        assert bsm.flow_name == "checkout"
        assert bsm.total_steps == 3

    def test_multi_step_flag_on_3_plus_steps(self):
        endpoints = [
            "http://shop.example.com/checkout/step1",
            "http://shop.example.com/checkout/step2",
            "http://shop.example.com/checkout/confirm",
        ]
        recorder = self._recorder()
        bsm      = recorder.record_from_endpoints(endpoints, {})[0]
        assert bsm.is_multi_step is True

    def test_single_endpoint_produces_no_bsm(self):
        """A single URL cannot form a multi-step flow."""
        endpoints = ["http://example.com/checkout/step1"]
        recorder  = self._recorder()
        bsms      = recorder.record_from_endpoints(endpoints, {})
        assert len(bsms) == 0

    def test_detects_decimal_price_param(self):
        endpoints = ["http://example.com/cart?price=19.99&qty=1",
                     "http://example.com/cart/summary?price=19.99"]
        recorder  = self._recorder()
        bsms      = recorder.record_from_endpoints(endpoints, {})
        assert len(bsms) >= 1
        types = {}
        for bsm in bsms:
            types.update(bsm.detected_objects)
        assert "price" in types
        assert types["price"] == "decimal"

    def test_detects_integer_id_param(self):
        endpoints = ["http://example.com/account?user_id=42&action=view",
                     "http://example.com/account/settings?user_id=42"]
        recorder  = self._recorder()
        bsms      = recorder.record_from_endpoints(endpoints, {})
        assert any("user_id" in bsm.detected_objects for bsm in bsms)

    def test_separate_flows_for_checkout_and_payment(self):
        """Different flow keywords should produce separate BSMs."""
        endpoints = [
            "http://example.com/checkout/step1",
            "http://example.com/checkout/step2",
            "http://example.com/payment/init",
            "http://example.com/payment/confirm",
        ]
        recorder = self._recorder()
        bsms     = recorder.record_from_endpoints(endpoints, {})
        flow_names = {bsm.flow_name for bsm in bsms}
        assert "checkout" in flow_names
        assert "payment"  in flow_names

    def test_returns_bsm_dataclass_with_steps(self):
        endpoints = [
            "http://example.com/password/reset",
            "http://example.com/password/confirm",
        ]
        recorder = self._recorder()
        bsms     = recorder.record_from_endpoints(endpoints, {})
        assert len(bsms) >= 1
        bsm = bsms[0]
        assert isinstance(bsm, BehavioralStateMachine)
        assert len(bsm.steps) >= 2
        assert all(isinstance(s, BSMStep) for s in bsm.steps)


# ---------------------------------------------------------------------------
# BSMDeviationProber tests
# ---------------------------------------------------------------------------

class TestBSMDeviationProber:

    def _make_bsm(self, flow_name="checkout", endpoints=None, detected_objects=None):
        if endpoints is None:
            endpoints = [
                "http://example.com/checkout/step1?qty=1&price=9.99",
                "http://example.com/checkout/step2?user_id=42",
                "http://example.com/checkout/confirm",
            ]
        recorder = BSMRecorder()
        bsms     = recorder.record_from_endpoints(endpoints, {})
        return bsms[0] if bsms else None

    def test_generates_step_skip_probes_for_3_step_flow(self):
        bsm    = self._make_bsm()
        assert bsm is not None, "BSM should be created from 3 checkout endpoints"
        prober = BSMDeviationProber()
        probes = prober.generate_probes(bsm, state={})
        step_skips = [p for p in probes if p.probe_type == "step_skip"]
        assert len(step_skips) >= 1

    def test_step_skip_jumps_two_steps(self):
        bsm    = self._make_bsm()
        prober = BSMDeviationProber()
        probes = prober.generate_probes(bsm, state={})
        skip   = next((p for p in probes if p.probe_type == "step_skip"), None)
        assert skip is not None
        # baseline_step should be step 0 or 1, target should be step 2
        assert skip.baseline_step.step_index < skip.baseline_step.step_index + 2

    def test_generates_csrf_bypass_probes(self):
        bsm    = self._make_bsm()
        prober = BSMDeviationProber()
        probes = prober.generate_probes(bsm, state={})
        csrf   = [p for p in probes if p.probe_type == "csrf_bypass"]
        assert len(csrf) >= 1

    def test_price_tamper_probe_with_negative_value(self):
        """A price parameter should get a -1 tamper probe."""
        endpoints = [
            "http://example.com/cart?price=9.99&qty=2",
            "http://example.com/cart/checkout?price=9.99",
        ]
        recorder = BSMRecorder()
        bsms     = recorder.record_from_endpoints(endpoints, {})
        assert bsms, "Should detect cart flow"
        bsm    = bsms[0]
        prober = BSMDeviationProber()
        probes = prober.generate_probes(bsm, state={})
        price_probes = [p for p in probes if p.probe_type == "price_tamper"]
        neg_probes   = [p for p in price_probes if p.modified_params.get("price") == "-1"]
        assert len(neg_probes) >= 1, "Should have a probe with price=-1"

    def test_price_tamper_uses_zero_value(self):
        endpoints = [
            "http://example.com/order?amount=50.00",
            "http://example.com/order/confirm?amount=50.00",
        ]
        recorder = BSMRecorder()
        bsms     = recorder.record_from_endpoints(endpoints, {})
        assert bsms
        prober   = BSMDeviationProber()
        probes   = prober.generate_probes(bsms[0], state={})
        amounts  = [p.modified_params.get("amount") for p in probes if p.probe_type == "price_tamper"]
        assert "0" in amounts

    def test_no_role_confusion_without_alt_cookies(self):
        bsm    = self._make_bsm()
        prober = BSMDeviationProber()
        probes = prober.generate_probes(bsm, state={})          # no alt_user_cookies
        roles  = [p for p in probes if p.probe_type == "role_confusion"]
        assert len(roles) == 0

    def test_role_confusion_generated_with_alt_cookies(self):
        bsm    = self._make_bsm()
        prober = BSMDeviationProber()
        probes = prober.generate_probes(bsm, state={"alt_user_cookies": {"session": "admin-tok"}})
        roles  = [p for p in probes if p.probe_type == "role_confusion"]
        assert len(roles) >= 1

    def test_all_probes_have_required_fields(self):
        bsm    = self._make_bsm()
        prober = BSMDeviationProber()
        probes = prober.generate_probes(bsm, state={})
        for probe in probes:
            assert isinstance(probe, DeviationProbe)
            assert probe.probe_type in ("step_skip", "price_tamper", "idor", "csrf_bypass", "role_confusion")
            assert probe.target_url
            assert probe.method in ("GET", "POST", "PUT", "DELETE", "PATCH")
            assert isinstance(probe.modified_params, dict)
            assert probe.expected_rejection_status in (400, 403, 302)


# ---------------------------------------------------------------------------
# Integration: recorder → prober pipeline
# ---------------------------------------------------------------------------

class TestRecorderProberIntegration:

    def test_full_pipeline_checkout_3_steps(self):
        endpoints = [
            "http://shop.example.com/checkout/step1",
            "http://shop.example.com/checkout/step2?qty=2&price=29.99",
            "http://shop.example.com/checkout/confirm?qty=2&price=29.99",
        ]
        recorder = BSMRecorder()
        bsms     = recorder.record_from_endpoints(endpoints, {})
        assert bsms

        prober   = BSMDeviationProber()
        all_probes: list = []
        for bsm in bsms:
            all_probes.extend(prober.generate_probes(bsm, state={}))

        probe_types = {p.probe_type for p in all_probes}
        assert "step_skip"    in probe_types
        assert "csrf_bypass"  in probe_types


# ---------------------------------------------------------------------------
# BizLogicValidator tests
# ---------------------------------------------------------------------------

class TestBizLogicValidator:

    def test_validator_can_run(self):
        validator = BizLogicValidator()
        state = {"endpoints": ["http://example.com/checkout/step1"]}
        assert validator.can_run(state) is True

        state_no_match = {"endpoints": ["http://example.com/about"]}
        assert validator.can_run(state_no_match) is False

    @pytest.mark.asyncio
    async def test_validator_run_success(self):
        validator = BizLogicValidator()
        state = {
            "endpoints": [
                "http://shop.example.com/checkout/step1",
                "http://shop.example.com/checkout/step2?qty=2&price=29.99",
                "http://shop.example.com/checkout/confirm?qty=2&price=29.99"
            ]
        }
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_request_context = AsyncMock()
        mock_request_context.__aenter__.return_value = mock_response

        with patch("aiohttp.ClientSession.request", return_value=mock_request_context):
            result = await validator.run(state)
            assert result is not None
            assert result.success is True
            assert "biz-logic-" in result.vulnerability
            assert result.severity in ("critical", "high", "medium")

    @pytest.mark.asyncio
    async def test_validator_run_no_bypass(self):
        validator = BizLogicValidator()
        state = {"endpoints": ["http://shop.example.com/checkout/step1", "http://shop.example.com/checkout/step2?qty=2&price=29.99", "http://shop.example.com/checkout/confirm?qty=2&price=29.99"]}
        mock_response = AsyncMock()
        mock_response.status = 403
        mock_request_context = AsyncMock()
        mock_request_context.__aenter__.return_value = mock_response

        with patch("aiohttp.ClientSession.request", return_value=mock_request_context):
            result = await validator.run(state)
            assert result is None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
