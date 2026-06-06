# ZENTRY-TRAIL — Project Context

## What this project is
An autonomous vulnerability validation platform. Full architecture documented in
avvp-build-plan.md. This file gives you the essential context for every session.

## What WORKS RIGHT NOW (do not rewrite these)
- core/orchestrator.py — main async pipeline (648 lines, working)
- core/ — 14 validators, session, scoring, signal extractor, chain expander (3,028 lines)
- modules/pipeline/ — recon, probing, discovery, scanning, brain, validation (17,352 lines)
- modules/recon/ — js_extractor, param_miner, reporting (6,538 lines)
- 122 tests passing in tests/
- Binaries in bin/: subfinder, httpx, gospider, gau, ffuf, dalfox (use these, don't download again)

## Key existing files to read before touching anything
- core/orchestrator.py — understand the full pipeline before extending
- modules/pipeline/brain/attack_chain_manager.py — existing chain logic
- modules/pipeline/brain/fact_store.py — how findings are stored
- modules/pipeline/validation/registry.py — how validators register
- modules/pipeline/validators/jwt_validator.py — example of a complete validator
- modules/pipeline/validators/race_condition_validator.py — threading-based validator pattern
- modules/pipeline/engine/models.py — ValidationResult, Evidence, ExecutionContext types

## What NEEDS to be built (avvp/services/ are all stubs)
Priority order:
1. OOB canary server — detects blind SSRF/SQLi/RCE (no OOB capability currently)
2. GraphQL + gRPC deep engines — extend existing graphql_validator.py
3. Traffic normalization — JA3/timing mimicry to bypass ML WAFs
4. Payload genetic engine — evolve payloads beyond template library
5. Behavioral baseline engine — detect business logic flaws
6. GNN + deadline-aware MCTS — replace basic DAGBrain
7. Autonomous chain synthesis — type resolver + causal learner + embedding reasoner
8. Self-training loop — scan outcome DB + GNN fine-tuner

## Coding conventions (match existing code exactly)
- Python 3.12, async/await throughout
- All validators: class with can_run(state) + run(state) → ValidationResult
- All findings stored via fact_store.add_confirmed_vulnerability()
- Use rich for all console output (progress.console.log)
- Import from modules.pipeline.engine.models: ValidationResult, Evidence, ExecutionContext
- Tests live in tests/ using pytest, no external services required for unit tests
- Never use bare except: — always except Exception as e: with logging

## Running the scanner
python main.py -u https://target.com --scope "target.com,api.target.com"

## Test command
python -m pytest tests/ --ignore=tests/test_api.py --ignore=tests/test_attack_graph.py \
  --ignore=tests/test_crawler.py --ignore=tests/test_osint.py \
  --ignore=tests/test_osint_crtsh.py --ignore=tests/test_phase7.py \
  --ignore=tests/test_priority_queue.py --ignore=tests/test_priority_queue_service.py \
  --ignore=tests/test_redis_dedup.py --tb=short -q
