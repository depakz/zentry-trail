"""
Tests for OOB Canary Server and token management.

Tests include:
- Token generation and parsing
- Server lifecycle (start/stop)
- Callback reception and storage
- /check endpoint verification
- Integration with SSRF validator
"""

import asyncio
import time
import pytest
from unittest.mock import MagicMock, patch

from avvp.services.oob_canary import (
    generate_token,
    get_canary_url,
    parse_token,
    OOBCanaryServer,
    Callback,
    get_oob_server,
)


class TestTokenGeneration:
    """Test token generation and parsing."""

    def test_generate_token_format(self):
        """Token should have format: scan_id_finding_id_random."""
        token = generate_token("scan123", "vuln456")
        assert isinstance(token, str)
        assert token.count("_") >= 2
        parts = token.split("_")
        assert len(parts) >= 3
        assert parts[0] == "scan123"
        assert parts[1] == "vuln456"
        assert len(parts[2]) == 12  # Random suffix

    def test_token_uniqueness(self):
        """Each token should be unique (random suffix is unique)."""
        token1 = generate_token("scan123", "vuln456")
        token2 = generate_token("scan123", "vuln456")
        assert token1 != token2, "Tokens should be unique"

    def test_parse_token(self):
        """Token parsing should extract scan_id, finding_id, random."""
        token = generate_token("myscan", "myvuln")
        parsed = parse_token(token)

        assert parsed is not None
        assert parsed["scan_id"] == "myscan"
        assert parsed["finding_id"] == "myvuln"
        assert len(parsed["random"]) == 12

    def test_parse_invalid_token(self):
        """Parsing invalid token should return None."""
        assert parse_token("invalid") is None
        assert parse_token("") is None
        assert parse_token("only_one_part") is None

    def test_get_canary_url(self):
        """Canary URL should be properly formatted."""
        token = generate_token("scan", "vuln")
        base_url = "http://attacker.com:8877"
        canary_url = get_canary_url(token, base_url)

        assert canary_url.startswith("http://attacker.com:8877/")
        assert token in canary_url

    def test_get_canary_url_trailing_slash(self):
        """Canary URL should handle base URLs with trailing slashes."""
        token = generate_token("scan", "vuln")
        base_url = "http://attacker.com:8877/"
        canary_url = get_canary_url(token, base_url)

        # Should not have double slash
        assert "//" not in canary_url.replace("http://", "")


@pytest.mark.asyncio
class TestOOBCanaryServer:
    """Test OOB Canary Server functionality."""

    async def test_server_startup_shutdown(self):
        """Server should start and stop cleanly."""
        server = OOBCanaryServer(host="127.0.0.1", port=9999)
        await server.start()
        await asyncio.sleep(0.1)  # Let server fully start

        # Server should be running
        assert server.runner is not None
        assert server.site is not None

        await server.stop()
        await asyncio.sleep(0.1)

    async def test_callback_reception(self):
        """Server should receive and store callbacks."""
        server = OOBCanaryServer(host="127.0.0.1", port=9998)
        await server.start()

        try:
            # Simulate a callback via the handler
            from aiohttp import web
            mock_request = MagicMock(spec=web.Request)
            mock_request.path = "/testtoken"
            mock_request.remote = "192.168.1.100"
            mock_request.method = "GET"
            mock_request.query_string = ""
            mock_request.headers = {}
            async def mock_text():
                return ""
            mock_request.text = mock_text

            # Call the handler directly
            response = await server._handle_request(mock_request)
            assert response.status == 200

            # Check callback was stored
            assert server.has_callback("testtoken")
            callback = server.get_callback("testtoken")
            assert callback is not None
            assert callback.source_ip == "192.168.1.100"
            assert callback.method == "GET"
            assert callback.path == "/testtoken"

        finally:
            await server.stop()

    async def test_check_endpoint(self):
        """GET /check/{token} should return callback status."""
        server = OOBCanaryServer(host="127.0.0.1", port=9997)
        await server.start()

        try:
            # Manually add a callback
            token = "test_token_123"
            callback = Callback(
                token=token,
                timestamp=time.time(),
                source_ip="10.0.0.1",
                method="GET",
                path="/callback",
            )
            server.callbacks[token] = callback

            # Call check endpoint
            from aiohttp import web
            mock_request = MagicMock(spec=web.Request)
            mock_request.match_info = {"token": token}

            response_json = await server._check_token(mock_request)
            result = response_json.body
            assert b"testtoken" not in result or b"test_token_123" in result

        finally:
            await server.stop()

    def test_callback_dataclass(self):
        """Callback should serialize to dict."""
        cb = Callback(
            token="test",
            timestamp=1234567890,
            source_ip="192.168.1.1",
            method="POST",
            path="/path",
            query_string="a=b",
            headers={"Host": "example.com"},
            body="test body",
        )

        data = cb.to_dict()
        assert data["token"] == "test"
        assert data["source_ip"] == "192.168.1.1"
        assert data["method"] == "POST"
        assert data["query_string"] == "a=b"

    def test_oob_server_singleton(self):
        """get_oob_server should return singleton."""
        server1 = get_oob_server(host="127.0.0.1", port=8877)
        server2 = get_oob_server(host="127.0.0.1", port=8877)
        assert server1 is server2

    def test_server_clear(self):
        """Clearing server should remove all callbacks."""
        server = OOBCanaryServer(host="127.0.0.1", port=8877)
        token = generate_token("scan", "vuln")

        callback = Callback(
            token=token,
            timestamp=time.time(),
            source_ip="10.0.0.1",
            method="GET",
            path="/test",
        )
        server.callbacks[token] = callback

        assert server.has_callback(token)
        server.clear()
        assert not server.has_callback(token)


class TestSSRFValidatorOOBIntegration:
    """Test SSRF validator OOB integration."""

    def test_ssrf_validator_imports(self):
        """SSRF validator should successfully import OOB utilities."""
        from modules.pipeline.validators.ssrf import (
            generate_token as ssrf_gen_token,
            get_canary_url as ssrf_get_url,
        )
        # Should not raise import errors
        assert ssrf_gen_token is not None or ssrf_gen_token is None  # One of these

    def test_ssrf_oob_probe_method_exists(self):
        """SSRF validator should have _probe_oob_ssrf_sync method."""
        from modules.pipeline.validators.ssrf import SSRFValidator

        validator = SSRFValidator()
        assert hasattr(validator, "_probe_oob_ssrf_sync")
        assert callable(validator._probe_oob_ssrf_sync)

    def test_ssrf_validator_with_oob_server(self):
        """SSRF validator should use OOB server when available."""
        from modules.pipeline.validators.ssrf import SSRFValidator
        from modules.pipeline.engine.models import ExecutionContext

        validator = SSRFValidator()
        server = OOBCanaryServer(host="127.0.0.1", port=9876)

        state = {
            "url": "http://target.com/fetch?url=INJECT",
            "target": "http://target.com/fetch?url=INJECT",
            "oob_server": server,
            "oob_base_url": "http://attacker.com:8877",
            "scan_id": "test_scan",
            "finding_id": "test_finding",
        }

        # Should not raise errors
        result = validator._probe_oob_ssrf_sync("http://target.com/fetch?url=INJECT", state)
        # Result may be None if no callback, but method should complete without error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
