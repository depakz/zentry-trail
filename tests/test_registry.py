import unittest

from modules.pipeline.validation import registry
from core.local_payload_engine import suggest_payloads


class RegistryTests(unittest.TestCase):
    def test_auto_discover_registers_validators(self):
        registry.auto_discover()
        # Expect some known validators to be present after discovery
        self.assertIn("xss", registry.VALIDATOR_REGISTRY)
        self.assertIn("sqli", registry.VALIDATOR_REGISTRY)
        self.assertTrue(callable(registry.VALIDATOR_REGISTRY["xss"]))

    def test_infer_vuln_types_uses_tags_and_params(self):
        registry.auto_discover()
        # nuclei tag mapping
        out = registry.infer_vuln_types(param="q", nuclei_tags=["xss", "sql"])
        self.assertIn("xss", out)
        self.assertIn("sqli", out)

        # param heuristics
        out2 = registry.infer_vuln_types(param="file_path", nuclei_tags=None)
        self.assertTrue(any(p in ("lfi", "path_traversal") for p in out2))

    def test_suggest_payloads_returns_defaults(self):
        p = suggest_payloads("xss", n=3)
        self.assertIsInstance(p, list)
        self.assertGreaterEqual(len(p), 1)
        self.assertIn("<script>alert(1)</script>", p)


if __name__ == "__main__":
    unittest.main()
