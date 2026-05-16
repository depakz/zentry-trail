## Summary

This PR integrates the local payload suggestion system into validators and the
attack variant catalog. It also adds unit tests to verify registry discovery and
payload suggestion fallbacks.

## Changes

- Wire `core.local_payload_engine.suggest_payloads()` into existing
  `modules/pipeline/validation/*_validator.py` modules with safe fallbacks.
- Enhance `modules/pipeline/brain/attack_variant_catalog.py` to include local
  suggestions for relevant payload categories.
- Add `core/bandit_agent.py`, `core/exploit_grammar.py`, and
  `core/local_payload_engine.py` to surface bandit/grammar-derived payloads.
- Add `tests/test_registry.py` and updated reward tests.

## Testing

- Ran unit tests: `python -m unittest discover -s tests -p 'test_*.py' -v` — all
  tests passed locally.

## Notes

- Remote RFI probes are gated by `RFI_CANARY_URL` environment variable.
- This change is best-effort: payload suggestions are used when available but do
  not break existing validator behavior.
