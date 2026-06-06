# ZENTRY-TRAIL — MASTER BUILD PROMPT
## Complete this file before starting any Claude Code session

---

## STEP 1 — Save this as CLAUDE.md in the repo root

Copy everything between the markers below and save as `/zentry-trail/CLAUDE.md`.
Claude Code reads this file automatically at the start of every session.

```
--- START CLAUDE.md ---

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

--- END CLAUDE.md ---
```

---

## STEP 2 — How to use the session prompts below

1. Open your terminal in the zentry-trail directory
2. Run: `claude` (starts Claude Code)
3. Paste the SESSION prompt for the phase you're working on
4. Let Claude Code read the files it needs, then implement
5. Run tests after each session before starting the next
6. Sessions build on each other — do them in order

Each session is designed to fit in one Claude Code context window (under 200K tokens).
Do not skip sessions — each one's output is used by the next.

---

---

# SESSION 1 — OOB Canary Server
**Time estimate:** 2–3 hours
**Why first:** Blind SSRF, blind SQLi, blind command injection are all invisible without OOB.
Every other session benefits from having this ready.

```
TASK: Build a complete Out-of-Band (OOB) canary server for zentry-trail.

FIRST read these files to understand the codebase:
1. core/orchestrator.py (understand the full pipeline)
2. modules/pipeline/validators/ssrf_validator.py (see how SSRF is currently detected)
3. modules/pipeline/brain/fact_store.py (understand FactStore)
4. modules/pipeline/engine/models.py (ValidationResult, Evidence types)
5. avvp/services/oob-canary/ (see the stub)

WHAT TO BUILD:

Part A — OOB Canary HTTP Server (oob_canary/server.py)
Create a lightweight HTTP server (using aiohttp) that:
- Listens on a configurable port (default 8877)
- Accepts any GET/POST request to any path
- Extracts a token from the path: format is /{scan_id}/{finding_id}/{random}
- Stores callbacks in memory: dict keyed by token → {timestamp, source_ip, method, path}
- Exposes GET /check/{token} endpoint that returns whether a callback was received
- Logs every callback with rich

Part B — Token generator (oob_canary/tokens.py)
- generate_token(scan_id, finding_id) → str (URL-safe, 12 random chars)
- get_canary_url(token, base_url) → str (full callback URL)
- A global OOBCanary singleton that manages the server lifecycle

Part C — Wire into existing SSRF validator
- Read modules/pipeline/validators/ and find the ssrf_validator
- Add OOB-based SSRF detection: inject canary URL into each URL-type parameter
- Wait up to 5 seconds after firing — poll /check/{token} to see if callback arrived
- If callback arrives → confirmed blind SSRF, return ValidationResult(success=True, confidence=0.99)

Part D — Wire into orchestrator startup
- In core/orchestrator.py __init__, start the OOB canary server if a local IP is available
- Pass canary base URL through state dict so all validators can use it
- Stop the server cleanly in a finally block

Part E — Tests (tests/test_oob_canary.py)
- Test token generation and parsing
- Test the /check endpoint with a simulated callback
- Test that the SSRF validator produces a confirmed finding when OOB callback arrives

ACCEPTANCE CRITERIA:
- python -m pytest tests/test_oob_canary.py -v → all pass
- Running the scanner against a test SSRF endpoint produces a "blind-ssrf-confirmed" finding
- The canary server starts and stops cleanly with the orchestrator
- Zero changes to the 122 existing passing tests
```

---

# SESSION 2 — GraphQL Deep Attack Engine
**Time estimate:** 2–3 hours
**Depends on:** Session 1 complete (uses OOB canary for blind injections)

```
TASK: Build a production-grade GraphQL attack engine for zentry-trail.

FIRST read these files:
1. modules/pipeline/validators/graphql_validator.py (existing GraphQL validator)
2. modules/pipeline/validation/base_validator.py (base class pattern)
3. modules/pipeline/validation/registry.py (how validators register)
4. modules/pipeline/validators/jwt_validator.py (example of a complete, well-structured validator)
5. modules/pipeline/engine/models.py

WHAT TO BUILD:

The existing graphql_validator.py likely does basic introspection. Extend it with:

Part A — Schema extraction without introspection (graphql_engine/schema_inference.py)
- Send partial field names and parse "Did you mean X?" error responses
- Reconstruct types/fields from suggestion errors
- Try: __type, __schema, __typename queries
- Field suggestion brute-force: try common field names (id, name, email, password, token,
  admin, user, users, me, viewer, query, mutation) against each type
- Return a SchemaMap: {type_name: [field_names]}

Part B — Attack methods (add to graphql_validator.py or create graphql_deep_validator.py)
1. Batch query abuse: send 500 aliased identical queries in one request
   → if all succeed, rate-limit bypass confirmed
2. Nested query depth DoS probe: query { user { posts { comments { author { posts {
   depth 2,4,8,16 → measure response time → if time grows exponentially, no depth limit
3. IDOR via object IDs: for every type with an id field, try:
   - query { user(id: 1) { email } } with authenticated session
   - query { user(id: 2) { email } } → if different user data returned, IDOR confirmed
4. Introspection on disabled endpoints: send __schema query with encoding variations
   (URL-encoded, persisted queries, GET vs POST, Content-Type variations)

Part C — gRPC engine (grpc_validator.py — new validator)
- Use grpcurl binary if available (check bin/ and PATH)
- Attempt server reflection: grpcurl -plaintext {host}:{port} list
- For each discovered method, probe with empty/malformed protobuf
- Check for unauthenticated methods (no auth header → 200 OK is a finding)
- Emit finding if reflection is enabled (information disclosure)

Part D — Register both validators
- Add to modules/pipeline/validation/registry.py auto-discovery
- Add signal detection: can_run() checks for "graphql" in endpoints or tech stack

Part E — Tests (tests/test_graphql_engine.py, tests/test_grpc_engine.py)
- Mock HTTP responses for introspection disabled + field suggestions
- Test batch query detection with a mock server
- Test schema reconstruction from suggestion errors

ACCEPTANCE CRITERIA:
- Both validators register and appear in registry.auto_discover()
- Test suite: python -m pytest tests/test_graphql_engine.py tests/test_grpc_engine.py -v → pass
- Schema inference test: given a mock "Did you mean 'email'?" response → correctly maps field
- Zero regression in existing 122 tests
```

---

# SESSION 3 — Payload Genetic Engine
**Time estimate:** 3–4 hours
**Depends on:** Sessions 1–2 complete

```
TASK: Build a payload genetic engine that evolves new attack payloads
beyond the static template library when standard payloads fail.

FIRST read these files:
1. core/orchestrator.py — understand how validators are called
2. modules/pipeline/validators/sqli_validator.py — see existing payload approach
3. modules/pipeline/validators/xss_validator.py — see existing payload approach
4. core/scoring.py — understand how findings are scored
5. avvp/services/genetic-engine/ (stub to replace)
6. avvp/services/diff-analyzer/ (stub to replace)

WHAT TO BUILD:

Part A — Differential Response Analyzer (core/diff_analyzer.py)
Wraps any HTTP probe and computes a behavioral delta vector:

class DeltaVector:
    time_delta_ms: int          # probe latency minus baseline latency
    status_code_change: str     # "200→500" format
    body_length_delta: int      # bytes added/removed
    reflection_present: bool    # payload string appears in response body
    error_class: str            # "db_error"|"auth_error"|"template_error"|"none"|"unknown"
    new_headers: list[str]      # headers in probe but not in baseline
    oob_triggered: bool         # set by OOB canary integration

    @property
    def fitness_score(self) -> float:
        # 0.0 to 1.0 — how "interesting" this response is
        # oob_triggered=True → 0.50 base
        # time_delta > 2000ms → +0.25
        # error_class != "none" → +0.10
        # reflection_present → +0.08
        # status_code_change → +0.05
        # body_length_delta > 200 → +0.02

class DifferentialAnalyzer:
    def analyze(self, baseline_response, probe_response, oob_triggered=False) -> DeltaVector

Part B — Structured payload representation (core/payload_gene.py)

@dataclass
class PayloadGene:
    vuln_class: str         # "SQLI" | "XSS" | "SSRF" | "SSTI" | "CMDI"
    core_payload: str       # the injection string
    encoding_layer: str     # "none"|"url"|"double_url"|"unicode"|"html_entity"|"hex"
    delimiter: str          # "'"|'"'|"`"|"--"|"/*"|"#"|none
    wrapper: str            # "none"|"json"|"xml"|"base64"
    null_byte: bool
    case_variant: str       # "none"|"upper"|"lower"|"mixed"

    def render(self) -> str:
        # Apply encoding, delimiter, wrapper in correct order
        # Return the final string value to inject into HTTP parameter

Part C — Genetic engine (core/genetic_engine.py)

class PayloadGeneticEngine:
    POPULATION_SIZE = 20
    MAX_GENERATIONS = 10
    SELECTION_TOP_K = 6     # top 30%

    def evolve(
        self,
        vuln_class: str,
        target_url: str,
        param_name: str,
        evaluator: Callable[[str], DeltaVector],  # fires actual HTTP request
        baseline_response,
        remaining_budget_seconds: float,
    ) -> tuple[str | None, float]:
        # Returns (winning_payload, confidence) or (None, 0.0) if not found
        # Seeds initial population from existing payload templates for vuln_class
        # Selection: top SELECTION_TOP_K by fitness_score
        # Crossover: swap encoding_layer + delimiter between two parents
        # Mutation: random structural perturbation (swap encoding, toggle null_byte, etc.)
        # Hard stop: if remaining_budget < 15 seconds, return best candidate so far
        # If fitness_score >= 0.95 → return immediately as confirmed

Part D — Wire into SQLi and XSS validators
In sqli_validator.py and xss_validator.py:
- If all standard payloads return fitness < 0.3:
  - Instantiate PayloadGeneticEngine
  - Call evolve() with remaining budget = (scan_start + 1200) - now
  - If evolve() returns a winning payload → use it to confirm the finding

Part E — Tests (tests/test_genetic_engine.py)
- Test PayloadGene.render() for each encoding/wrapper combination
- Test DifferentialAnalyzer.analyze() with mock responses
- Test evolve() with a mock evaluator that returns high fitness for a specific payload structure
- Test hard budget stop: evolve() with 5-second budget → returns before generation 10

ACCEPTANCE CRITERIA:
- tests/test_genetic_engine.py → all pass
- evolve() with a mock that rewards hex-encoded payloads → correctly selects hex encoding
- Hard budget stop: no generation runs past the budget
- Zero regression in existing tests
- PayloadGene.render() correctly applies: double_url encoding → delimiter → base64 wrapper
```

---

# SESSION 4 — Behavioral Baseline Engine
**Time estimate:** 3–4 hours
**Depends on:** Sessions 1–3 complete

```
TASK: Build a behavioral baseline engine that records normal application
behavior during authenticated recon, then probes for business logic flaws.

FIRST read these files:
1. core/orchestrator.py — understand the full pipeline and state dict
2. modules/pipeline/validators/idor_validator.py — existing IDOR detection approach
3. modules/pipeline/brain/fact_store.py — how to store findings
4. modules/recon/modules/js_extractor.py — understand how recon flows work
5. avvp/services/behavioral-baseline/ (stub to understand intent)

WHAT TO BUILD:

Part A — Behavioral State Machine recorder (core/behavioral_baseline.py)

@dataclass
class BSMStep:
    url: str
    method: str
    param_snapshot: dict        # parameter name → value at this step
    response_status: int
    response_time_ms: int
    session_cookies: dict
    step_index: int

@dataclass
class BehavioralStateMachine:
    flow_name: str              # "checkout" | "password_reset" | "account_settings" etc.
    steps: list[BSMStep]
    total_steps: int
    requires_auth: bool
    detected_objects: dict      # {param_name: type} e.g. {"user_id": "integer", "price": "decimal"}

class BSMRecorder:
    def record_from_endpoints(self, endpoints: list[str], state: dict) -> list[BehavioralStateMachine]:
        # Groups endpoints into flows by URL path prefix similarity
        # For each flow, orders steps by URL depth and infers step sequence
        # Extracts numeric/money parameters that could be tampered
        # Identifies multi-step flows (3+ related URLs) as candidates for workflow bypass

Part B — Deviation probe generator (core/behavioral_probe.py)

class BSMDeviationProber:
    def generate_probes(self, bsm: BehavioralStateMachine, state: dict) -> list[DeviationProbe]:
        probes = []
        # 1. Workflow step skip: for each step N, try to jump directly to step N+2
        # 2. Price/quantity tampering: for decimal/integer params, try:
        #    - negative values (-1, -999)
        #    - zero (0)
        #    - extremely large (999999)
        #    - fractional if integer expected (1.5)
        # 3. Horizontal IDOR: for user_id/account_id params, try adjacent IDs (current±1)
        # 4. CSRF token removal: replay step without any X-CSRF-Token header
        # 5. Role confusion: if two user roles exist in scope, swap session cookies

@dataclass
class DeviationProbe:
    probe_type: str             # "step_skip"|"price_tamper"|"idor"|"csrf_bypass"|"role_confusion"
    target_url: str
    method: str
    modified_params: dict
    baseline_step: BSMStep
    expected_rejection_status: int  # 403, 400, or 302

Part C — Business logic validator (modules/pipeline/validators/biz_logic_validator.py)
Following the exact pattern of jwt_validator.py:

class BizLogicValidator:
    SIGNALS = {
        "endpoint_patterns": ["/checkout", "/cart", "/order", "/payment", "/account",
                               "/password", "/profile", "/transfer", "/redeem"],
    }
    validator_id = "biz_logic_validator"
    priority = 85

    def can_run(self, state) -> bool: ...

    async def run(self, state) -> ValidationResult | None:
        # 1. Run BSMRecorder on state["endpoints"]
        # 2. Run BSMDeviationProber on each detected flow
        # 3. Fire each probe as an HTTP request
        # 4. If response status is 200 (expected rejection didn't happen) → finding
        # 5. Severity mapping:
        #    price_tamper confirmed → critical
        #    step_skip confirmed → high
        #    horizontal_idor confirmed → high
        #    csrf_bypass confirmed → medium

Part D — Wire into orchestrator
In core/orchestrator.py, add BizLogicValidator to the validator pool.
It runs during Phase 2 validation, same as all other validators.

Part E — Tests (tests/test_biz_logic_validator.py)
- Test BSMRecorder groups /checkout/step1, /checkout/step2, /checkout/confirm into one flow
- Test BSMDeviationProber generates step_skip probes for a 3-step flow
- Test price tamper probe with negative value
- Mock HTTP: server returns 200 to a negative price probe → validator confirms finding

ACCEPTANCE CRITERIA:
- BizLogicValidator appears in registry.auto_discover()
- tests/test_biz_logic_validator.py → all pass
- BSMRecorder correctly identifies a 3-step checkout flow from endpoint list
- Price tamper probe fires with value "-1" and correctly interprets 200 response as confirmed
- Zero regression in existing 122 tests
```

---

# SESSION 5 — Traffic Normalization Engine
**Time estimate:** 2–3 hours
**Depends on:** Sessions 1–4 complete

```
TASK: Build a traffic normalization layer that makes scanner requests
look like real browser traffic to evade ML-based WAF detection.

FIRST read these files:
1. core/orchestrator.py — find where HTTP requests are made
2. modules/pipeline/probing/httpx_probe.py — understand HTTP probing
3. modules/pipeline/validators/ssrf_validator.py — see how requests are fired
4. core/utils.py — existing HTTP utilities

WHAT TO BUILD:

Part A — JA3/browser profile loader (core/traffic_profiles.py)

BROWSER_PROFILES = {
    "chrome124": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
        "header_order": ["Host", "Connection", "Cache-Control", "sec-ch-ua",
                         "sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests",
                         "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                         "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"],
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,...",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br, zstd",
        "sec_fetch_site": "none",
        "sec_fetch_mode": "navigate",
        "connection": "keep-alive",
    },
    "firefox124": { ... },  # fill in Firefox 124 headers
    "safari17": { ... },    # fill in Safari 17 headers
}

Part B — Timing engine (core/timing_engine.py)
class GaussianTimer:
    # Inter-request delays drawn from N(mean=800ms, sigma=400ms)
    # Clamped to [50ms, 5000ms]
    # Two modes:
    # - "browse": simulates human navigation (mean=800ms) — used between page requests
    # - "api": simulates programmatic API calls (mean=80ms, sigma=20ms) — used for API endpoints

    def wait(self, mode: str = "browse") -> None:
        # Draw from the appropriate distribution and sleep

    def should_inject_noise_request(self) -> bool:
        # Return True with probability 0.08 (1 in 12 requests is "noise")

class NoiseRequestInjector:
    NOISE_PATHS = ["/favicon.ico", "/robots.txt", "/sitemap.xml",
                   "/static/main.js", "/assets/logo.png", "/css/style.css"]

    async def inject_if_needed(self, base_url: str, session: aiohttp.ClientSession):
        # Fire a benign GET request to a static asset path
        # This makes traffic look like a real browser loading page resources

Part C — Normalized HTTP client (core/normalized_client.py)
class NormalizedHTTPClient:
    def __init__(self, profile_name: str = "chrome124", mode: str = "browse"):
        self.profile = BROWSER_PROFILES[profile_name]
        self.timer = GaussianTimer()
        self.noise_injector = NoiseRequestInjector()
        self.session: aiohttp.ClientSession = None

    async def __aenter__(self):
        # Build aiohttp session with browser headers in correct order

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        await self.timer.wait(self.mode)
        if self.noise_injector.should_inject_noise_request():
            await self.noise_injector.inject_if_needed(url, self.session)
        return await self.session.get(url, headers=self._ordered_headers(), **kwargs)

    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        await self.timer.wait("api")  # POST = API call mode
        return await self.session.post(url, headers=self._ordered_headers(), **kwargs)

    def _ordered_headers(self) -> dict:
        # Return headers in the browser profile's exact order
        # Python dicts preserve insertion order since 3.7

Part D — Wire into validators selectively
Add an optional NormalizedHTTPClient to the state dict in orchestrator.py:
  state["normalized_client"] = NormalizedHTTPClient(profile_name="chrome124")
Validators that detect WAF blocking (403 responses) should switch to the normalized client.
Modify the WAF evasion in ssrf_validator.py to use normalized_client if available.

Part E — Tests (tests/test_traffic_normalization.py)
- Test GaussianTimer: 100 samples should have mean between 600–1000ms
- Test header ordering: chrome124 profile has User-Agent before Accept
- Test noise injection: over 100 calls, inject rate is between 5% and 15%
- Test NormalizedHTTPClient builds correct header order (mock aiohttp)

ACCEPTANCE CRITERIA:
- tests/test_traffic_normalization.py → all pass
- GaussianTimer timing distribution test passes (mean within expected range)
- Header ordering exactly matches browser profile spec
- NormalizedHTTPClient context manager starts and closes cleanly
- Zero regression in existing tests
```

---

# SESSION 6 — GNN + Deadline-Aware MCTS Decision Engine
**Time estimate:** 4–5 hours
**Depends on:** Sessions 1–5 complete
**This is the hardest session — take your time**

```
TASK: Build a GNN policy network + deadline-aware MCTS planner to replace
the current DAGBrain and make validation sequence selection data-driven.

FIRST read these files (carefully, all of them):
1. modules/pipeline/brain/dag_engine_enhanced.py — what you're replacing/augmenting
2. modules/pipeline/brain/attack_chain_manager.py — how chains work now
3. modules/pipeline/brain/fact_store.py — state storage
4. modules/pipeline/brain/graph_builder.py — existing graph logic
5. core/orchestrator.py lines 400-648 — how DAGBrain is used
6. avvp/services/gnn-engine/ (stub to implement)
7. avvp/services/mcts-planner/ (stub to implement)

WHAT TO BUILD:

Part A — Attack graph node features (core/attack_graph.py)
class AttackGraphNode:
    node_id: str                # sha256(endpoint_url)
    url: str
    canonical_url: str          # /api/user/{id} instead of /api/user/123
    auth_required: bool
    tech_stack: dict
    parameters: list[dict]      # [{"name": "id", "type": "integer", "location": "query"}]
    priority_score: float
    confirmed_findings: list[str]   # finding IDs from this endpoint
    output_artifacts: list[dict]    # [{type: "CREDENTIAL:JWT", value: "..."}]
    feature_vector: np.ndarray  # 32-dim, computed by featurize()

    def featurize(self) -> np.ndarray:
        # Returns 32-dim float vector for GNN input:
        # [0:4]   HTTP method one-hot (GET, POST, PUT, DELETE)
        # [4:8]   parameter type distribution (int, string, uuid, url)
        # [8:12]  tech stack one-hot (rails, django, spring, express, laravel, other*2)
        # [12:16] auth method one-hot (none, cookie, bearer, apikey)
        # [16:20] status code bucket (2xx, 3xx, 4xx, 5xx)
        # [20:24] latency quantile (fast<100ms, medium<500ms, slow<2s, very_slow)
        # [24:28] priority flags (admin_path, payment_path, file_upload, id_param)
        # [28:32] finding flags (confirmed_finding, chain_depth, has_artifacts, in_scope)

class AttackGraph:
    def __init__(self):
        self.nodes: dict[str, AttackGraphNode] = {}
        self.edges: list[tuple[str, str, float]] = []  # (from_id, to_id, confidence)

    def add_from_state(self, state: dict) -> None:
        # Build graph from orchestrator state dict
        # Create nodes from state["endpoints"]
        # Add edges based on: shared URL prefix, parameter references, tech stack similarity

    def to_adjacency_matrix(self) -> tuple[np.ndarray, np.ndarray]:
        # Returns (node_features [N x 32], adjacency [N x N]) for GNN

    def get_priority_ordered_nodes(self) -> list[AttackGraphNode]:
        # Returns nodes sorted by priority_score descending

Part B — Lightweight GNN (core/gnn_model.py)
Use numpy only — no PyTorch required (keeps dependencies minimal):

class SimpleGNN:
    """
    2-layer Graph Attention Network approximated with numpy.
    Input:  node features (N x 32)
    Output: per-node policy scores (N x 1) + graph value estimate (scalar)
    Pre-trained weights loaded from core/gnn_weights.npz if it exists.
    Falls back to priority_score if no weights found (graceful degradation).
    """
    def __init__(self, weights_path: str = "core/gnn_weights.npz"):
        self.weights_path = weights_path
        self.W1 = None  # 32 x 64 weight matrix
        self.W2 = None  # 64 x 1 weight matrix
        self._load_weights()

    def _load_weights(self):
        if os.path.exists(self.weights_path):
            data = np.load(self.weights_path)
            self.W1 = data["W1"]
            self.W2 = data["W2"]
        else:
            # Random init — model works but needs training to be useful
            rng = np.random.default_rng(42)
            self.W1 = rng.standard_normal((32, 64)) * 0.1
            self.W2 = rng.standard_normal((64, 1)) * 0.1

    def forward(self, node_features: np.ndarray, adjacency: np.ndarray) -> tuple[np.ndarray, float]:
        # Layer 1: aggregate neighbor features via adjacency, apply W1
        # Layer 2: apply W2
        # Returns (per-node policy logits, graph value estimate)

    def save_weights(self):
        np.savez(self.weights_path, W1=self.W1, W2=self.W2)

Part C — Deadline-aware MCTS (core/mcts_planner.py)

class DeadlineAwareMCTS:
    C_MAX = 1.4     # exploration weight at scan start
    C_MIN = 0.05    # exploitation weight at deadline

    def __init__(self, gnn: SimpleGNN, scan_deadline_epoch: float):
        self.gnn = gnn
        self.deadline = scan_deadline_epoch
        self.scan_start = time.time()

    def exploration_constant(self) -> float:
        elapsed_frac = (time.time() - self.scan_start) / max(1, self.deadline - self.scan_start)
        elapsed_frac = min(1.0, elapsed_frac)
        # Sigmoid decay
        return self.C_MIN + (self.C_MAX - self.C_MIN) / (1 + math.exp(10 * (elapsed_frac - 0.6)))

    def plan(self, graph: AttackGraph, budget_seconds: float = 60) -> list[AttackGraphNode]:
        """
        Returns an ordered list of nodes to validate, prioritized by expected value.
        Runs MCTS for min(budget_seconds, remaining_time * 0.3) seconds.
        Falls back to graph.get_priority_ordered_nodes() if time budget < 5s.
        """
        if self.deadline - time.time() < 5:
            return graph.get_priority_ordered_nodes()

        node_features, adjacency = graph.to_adjacency_matrix()
        if node_features.size == 0:
            return graph.get_priority_ordered_nodes()

        policy_logits, value = self.gnn.forward(node_features, adjacency)
        # Sort nodes by policy logit descending
        node_list = list(graph.nodes.values())
        scored = sorted(zip(policy_logits.flatten(), node_list), reverse=True)
        return [node for _, node in scored]

Part D — Wire into orchestrator
In core/orchestrator.py:
- Import AttackGraph, DeadlineAwareMCTS, SimpleGNN
- After recon phase completes, build AttackGraph from state
- Create DeadlineAwareMCTS with deadline = scan_start + 1200 (20 min)
- Call plan() to get ordered node list → use this order for validation dispatch
- Keep DAGBrain as a fallback if MCTS returns empty

Part E — Weight update after scan (core/gnn_trainer.py)
class PostScanTrainer:
    def update(self, gnn: SimpleGNN, confirmed_findings: list[Finding],
               node_order_used: list[AttackGraphNode]) -> None:
        """
        Simple gradient update: nodes that led to confirmed findings get
        their policy scores increased via a small weight nudge.
        10-step gradient descent, learning rate 0.001.
        Saves updated weights back to gnn_weights.npz.
        """

Part F — Tests (tests/test_mcts_planner_v2.py)
- Test AttackGraphNode.featurize() produces a 32-dim vector
- Test AttackGraph.add_from_state() with a mock state dict
- Test DeadlineAwareMCTS.exploration_constant() decays from 1.4 to 0.05 over scan
- Test plan() with a 5-node graph → returns all nodes in policy score order
- Test plan() with expired deadline → falls back to priority ordering

ACCEPTANCE CRITERIA:
- tests/test_mcts_planner_v2.py → all pass
- exploration_constant() at t=0 returns ≥ 1.3, at t=deadline returns ≤ 0.1
- plan() on a 10-node graph returns exactly 10 nodes in descending policy score order
- GNN weights save/load round-trip correctly
- Zero regression in existing tests
- Scanner still completes a full run with MCTS in the loop
```

---

# SESSION 7 — Autonomous Chain Synthesis
**Time estimate:** 4–5 hours
**Depends on:** Sessions 1–6 complete
**This replaces the static attack_chain_manager predicates with autonomous reasoning**

```
TASK: Build the three-engine autonomous chain synthesis system that discovers
attack chains without any manually written rules.

FIRST read these files:
1. modules/pipeline/brain/attack_chain_manager.py — what you're extending
2. modules/pipeline/brain/chaining_orchestrator.py — existing chain orchestration
3. modules/pipeline/brain/fact_store.py — confirmed vulnerability storage
4. core/orchestrator.py — how chain results feed back into findings
5. libs/artifact-types/types.py (in avvp/) — the artifact type system
6. avvp/services/type-resolver/ — stub to implement
7. avvp/services/embedding-reasoner/ — stub to implement
8. avvp/services/state-propagator/ — stub to implement

WHAT TO BUILD:

Part A — Artifact Type System (core/artifact_types.py)
Copy from avvp/libs/artifact-types/types.py and complete it:

ALL_OUTPUT_TYPES = {
    "CREDENTIAL:AWS_KEY", "CREDENTIAL:GCP_SA_TOKEN", "CREDENTIAL:API_KEY",
    "CREDENTIAL:SESSION_TOKEN", "CREDENTIAL:JWT_SIGNED", "CREDENTIAL:DB_CONNECTION_STRING",
    "ENDPOINT:INTERNAL_URL", "ENDPOINT:INTERNAL_IP", "ENDPOINT:KUBERNETES_API",
    "ENDPOINT:CLOUD_METADATA_URL", "ENDPOINT:DATABASE_HOST", "ENDPOINT:SERVICE_NAME",
    "IDENTITY:USER_ID", "IDENTITY:ORG_ID", "IDENTITY:ROLE_NAME", "IDENTITY:PERMISSION_SCOPE",
    "PATH:FILE_PATH", "PATH:CONFIG_PATH", "PATH:WEBROOT_PATH", "PATH:S3_ARN",
    "EXEC:EVAL_CONTEXT", "EXEC:TEMPLATE_CONTEXT", "EXEC:DESERIALIZATION_HANDLE",
    "DATA:PII_RECORD", "DATA:SECRET_VALUE", "DATA:INTERNAL_CONFIG",
}

# Which attack types accept which input artifact type
ATTACK_REQUIRES: dict[str, list[str]] = {
    "ssrf_internal":         ["ENDPOINT:INTERNAL_URL", "ENDPOINT:INTERNAL_IP"],
    "cloud_credential_abuse":["CREDENTIAL:AWS_KEY", "CREDENTIAL:GCP_SA_TOKEN"],
    "file_read":             ["PATH:FILE_PATH", "PATH:CONFIG_PATH"],
    "webshell_via_upload":   ["PATH:WEBROOT_PATH"],
    "horizontal_idor":       ["IDENTITY:USER_ID", "IDENTITY:ORG_ID"],
    "privilege_escalation":  ["IDENTITY:ROLE_NAME", "IDENTITY:PERMISSION_SCOPE"],
    "rce_deserialization":   ["EXEC:DESERIALIZATION_HANDLE"],
    "ssti":                  ["EXEC:TEMPLATE_CONTEXT"],
    "k8s_api_attack":        ["ENDPOINT:KUBERNETES_API"],
    "db_direct_access":      ["CREDENTIAL:DB_CONNECTION_STRING", "ENDPOINT:DATABASE_HOST"],
    "internal_pivot":        ["ENDPOINT:SERVICE_NAME", "ENDPOINT:INTERNAL_IP"],
}

def extract_artifacts_from_finding(finding: Finding, response_text: str) -> list[dict]:
    """
    Extracts typed artifacts from a confirmed finding's response.
    Patterns:
    - AWS key regex → CREDENTIAL:AWS_KEY
    - 169.254.x.x in response → ENDPOINT:CLOUD_METADATA_URL
    - Internal IP regex (10.x, 172.16-31.x, 192.168.x) → ENDPOINT:INTERNAL_IP
    - /etc/passwd content → DATA:INTERNAL_CONFIG
    - JWT in response → CREDENTIAL:JWT_SIGNED
    - DB connection string → CREDENTIAL:DB_CONNECTION_STRING
    Returns list of {"type": "...", "value": "..."}
    """

Part B — Type Compatibility Resolver (core/type_resolver.py)
class TypeCompatibilityResolver:
    def resolve(self, artifacts: list[dict]) -> list[ChainCandidate]:
        """
        For each artifact, find all attacks whose required input type matches.
        Confidence = 1.0 for exact match, 0.7 for category match (CREDENTIAL:* matches any CREDENTIAL)
        Returns list of ChainCandidate sorted by confidence descending.
        Sub-millisecond — pure dict lookup, no ML required.
        """

@dataclass
class ChainCandidate:
    source_finding_id: str
    attack_type: str
    artifact: dict
    confidence: float           # 0.0–1.0
    source: str                 # "type_resolver" | "embedding_reasoner"
    chain_plan: dict            # {"action": "attack_type", "input": artifact["value"]}

Part C — Embedding-based zero-shot reasoner (core/embedding_reasoner.py)
Use sentence-transformers if available, fall back to TF-IDF cosine similarity:

class EmbeddingReasoner:
    """
    Finds semantic chain candidates when type system has no match.
    Uses sentence-transformers/all-MiniLM-L6-v2 (22MB, no GPU needed).
    Falls back to TF-IDF + cosine similarity if sentence-transformers not installed.
    """
    ATTACK_DESCRIPTIONS = {
        "ssrf_internal":         "Server-Side Request Forgery to reach internal network URLs and IPs",
        "cloud_credential_abuse":"Using cloud provider API keys or tokens to access cloud resources",
        "file_read":             "Reading arbitrary files from the filesystem using path parameters",
        # ... one description per attack type in ATTACK_REQUIRES
    }

    def find_candidates(self, artifact: dict, threshold: float = 0.60) -> list[ChainCandidate]:
        artifact_desc = f"{artifact['type']}: {artifact.get('value', '')[:100]}"
        # Embed artifact description + each attack description
        # Return attacks with cosine similarity > threshold
        # Confidence = cosine_similarity score

Part D — Exploit State Propagator (core/state_propagator.py)
class ExploitStatePropagator:
    def __init__(self, attack_graph: AttackGraph, type_resolver: TypeCompatibilityResolver,
                 embedding_reasoner: EmbeddingReasoner):
        ...

    def on_finding_confirmed(self, finding: Finding, response_text: str,
                             fact_store: FactStore) -> list[ChainCandidate]:
        """
        Called after every confirmed finding.
        1. Extract typed artifacts from finding + response_text
        2. Run type_resolver.resolve(artifacts) → high-confidence candidates
        3. Run embedding_reasoner.find_candidates() for any artifact with no type match
        4. Merge and deduplicate candidates
        5. Store artifacts in fact_store for downstream use
        6. Return sorted candidate list
        """

    def build_chain_plan(self, candidate: ChainCandidate, state: dict) -> dict | None:
        """
        Translates a chain candidate into an executable plan:
        {"validator": "ssrf_validator", "target": "http://...", "inject_value": "10.0.0.1"}
        Returns None if the plan can't be built from available state.
        """

Part E — Wire into orchestrator
In core/orchestrator.py, after each confirmed finding:
1. Call propagator.on_finding_confirmed(finding, response_text, fact_store)
2. For Tier A candidates (confidence ≥ 0.85): immediately fire as a follow-up validation
3. For Tier B candidates (0.50–0.85): add to a follow-up queue executed after main validation
4. For Tier C candidates (<0.50): log for reporting but don't execute unless time permits

Part F — Tests (tests/test_chain_synthesis.py)
- Test extract_artifacts_from_finding: mock response with AWS key → CREDENTIAL:AWS_KEY artifact
- Test TypeCompatibilityResolver: CREDENTIAL:AWS_KEY → cloud_credential_abuse (confidence 1.0)
- Test category match: CREDENTIAL:GCP_SA_TOKEN → cloud_credential_abuse (confidence 1.0)
- Test EmbeddingReasoner: "AWS key material for S3 access" embeds near cloud_credential_abuse
- Test ExploitStatePropagator: SSRF confirmed with 10.0.0.1 in response → ssrf_internal chain candidate

ACCEPTANCE CRITERIA:
- tests/test_chain_synthesis.py → all pass
- AWS key regex correctly extracted from a mock SSRF response
- Type resolver resolves ENDPOINT:INTERNAL_IP to ssrf_internal in < 1ms
- Embedding reasoner (TF-IDF fallback) scores "internal network IP address" > 0.60 against ssrf_internal
- Full integration: confirming an SSRF finding with an internal IP in the response auto-queues an ssrf_internal chain
- Zero regression in existing tests
```

---

# SESSION 8 — Evidence Store + Cryptographic Signing
**Time estimate:** 2–3 hours
**Depends on:** Sessions 1–7 complete

```
TASK: Build a tamper-evident evidence storage system for all confirmed findings.

FIRST read these files:
1. modules/recon/reporting/html_report.py — existing reporting
2. modules/recon/reporting/json_report.py — existing JSON output
3. core/session.py — how findings and sessions are stored
4. avvp/services/evidence_store/ — stub to implement

WHAT TO BUILD:

Part A — Evidence store (core/evidence_store.py)
class EvidenceStore:
    """
    Stores all confirmed finding evidence with cryptographic signing.
    Uses local filesystem (reports/evidence/) — no S3 dependency.
    Signs with ECDSA P-256 using a session key generated at scan start.
    """
    def __init__(self, output_dir: str = "reports/evidence"):
        self.output_dir = output_dir
        self.private_key, self.public_key = self._generate_session_key()
        self.manifest: dict[str, SignedRef] = {}

    def _generate_session_key(self):
        # Generate ephemeral ECDSA P-256 key pair for this scan session
        # Use: from cryptography.hazmat.primitives.asymmetric import ec

    def store_artifact(self, finding_id: str, artifact_type: str,
                       content: bytes) -> SignedRef:
        """
        1. Hash content with SHA-256
        2. Build signing message: f"{content_hash}:{finding_id}:{artifact_type}:{timestamp}"
        3. Sign message with ECDSA private key
        4. Save content to: {output_dir}/{finding_id}/{artifact_type}_{content_hash[:8]}
        5. Return SignedRef with content_hash, signature, timestamp
        """

    def store_http_pair(self, finding_id: str, request_dict: dict,
                        response_dict: dict) -> tuple[SignedRef, SignedRef]:
        """Store the HTTP request+response pair as JSON evidence."""

    def generate_bundle(self, finding_id: str) -> EvidenceBundle:
        """
        Collect all artifacts for a finding into a verifiable bundle.
        Bundle includes a Merkle tree over artifact hashes.
        Bundle written to: {output_dir}/{finding_id}/bundle.json
        """

    def verify_bundle(self, finding_id: str) -> bool:
        """Verify all signatures in a bundle using the session public key."""

@dataclass
class SignedRef:
    s3_key: str             # local path used as key
    content_hash: str
    signature: str          # hex-encoded ECDSA signature
    signed_at: int          # epoch timestamp
    artifact_type: str

Part B — Wire into finding collection
In core/orchestrator.py:
- Instantiate EvidenceStore once in __init__
- After each confirmed Finding: call evidence_store.store_http_pair(finding.id, ...)
- At scan end: call evidence_store.generate_bundle() for each finding
- Add bundle paths to Finding objects for reporting

Part C — Enhanced SARIF output (core/sarif_reporter.py)
class SARIFReporter:
    def generate(self, session: Session, evidence_store: EvidenceStore) -> dict:
        """
        Produces SARIF 2.1 compliant output.
        Each finding → one sarif Result with:
        - rule_id: vuln_class
        - level: "error"|"warning"|"note" (mapped from severity)
        - locations: [physicalLocation with uri]
        - properties: cvss_score, evidence_bundle_path, confirmed_payload
        - relatedLocations: for chain findings, references the parent finding
        Writes to reports/{scan_id}.sarif
        """

    def _cvss_score(self, severity: str) -> float:
        # critical → 9.5, high → 8.0, medium → 5.5, low → 3.0, info → 0.0

Part D — Tests (tests/test_evidence_store_v2.py)
- Test key pair generation: private + public key generated successfully
- Test store_artifact: content saved, signature verifiable with public key
- Test verify_bundle: tamper a stored artifact → verify_bundle returns False
- Test SARIFReporter: mock session with 2 findings → valid SARIF 2.1 JSON output

ACCEPTANCE CRITERIA:
- tests/test_evidence_store_v2.py → all pass
- verify_bundle(finding_id) returns True for untampered bundle
- verify_bundle returns False if any artifact byte is changed
- SARIF output validates against SARIF 2.1 schema (use jsonschema)
- Evidence bundles written to reports/evidence/ for every confirmed finding
- Zero regression in existing tests
```

---

# SESSION 9 — Self-Training Loop
**Time estimate:** 3–4 hours
**Depends on:** Sessions 1–8 complete

```
TASK: Build the self-training loop that makes the GNN improve after every scan.

FIRST read these files:
1. core/gnn_model.py (built in Session 6) — the model to train
2. core/gnn_trainer.py (built in Session 6) — the basic trainer
3. core/mcts_planner.py (built in Session 6) — uses the model
4. core/orchestrator.py — where scan outcomes are collected
5. avvp/services/scan-outcome-db/ — schema to implement
6. avvp/services/gnn_trainer/ — extended trainer stub

WHAT TO BUILD:

Part A — Scan outcome database (core/outcome_db.py)
Use SQLite (no PostgreSQL dependency for local deployments):

class OutcomeDB:
    """
    SQLite database tracking scan outcomes for GNN training.
    Written to: data/outcomes.db
    """
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        target TEXT, started_at INTEGER, completed_at INTEGER,
        endpoint_count INTEGER, finding_count INTEGER,
        false_positive_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY, scan_id TEXT,
        vuln_class TEXT, endpoint_url TEXT, confidence REAL,
        confirmed INTEGER DEFAULT 0,   -- 1=TP, 0=FP, NULL=unknown
        chain_depth INTEGER DEFAULT 1,
        parent_finding_id TEXT,
        created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS node_decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT, node_id TEXT, policy_score REAL,
        validation_order INTEGER,       -- what position in the scan plan
        led_to_finding INTEGER DEFAULT 0,   -- 1 if this node produced a confirmed finding
        created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS attack_win_rates (
        strategy_id TEXT, tech_stack TEXT, waf_provider TEXT,
        attempts INTEGER DEFAULT 0, successes INTEGER DEFAULT 0,
        PRIMARY KEY (strategy_id, tech_stack, waf_provider)
    );
    """

    def record_scan(self, scan_id, target, started_at): ...
    def record_finding(self, finding: Finding, scan_id: str): ...
    def record_node_decision(self, scan_id, node_id, policy_score, order, led_to_finding): ...
    def update_win_rate(self, strategy_id, tech_stack, waf_provider, success: bool): ...
    def get_training_data(self, scan_id: str) -> list[dict]: ...
    def label_false_positive(self, finding_id: str): ...

Part B — Post-scan GNN fine-tuner (core/gnn_fine_tuner.py)
class PostScanFineTuner:
    """
    Runs after every scan completes. Not on critical path — called in background.
    Updates GNN weights based on which nodes led to confirmed findings.
    """
    LEARNING_RATE = 0.001
    N_STEPS = 20

    def fine_tune(self, gnn: SimpleGNN, scan_id: str, db: OutcomeDB) -> SimpleGNN:
        training_data = db.get_training_data(scan_id)
        if len(training_data) < 3:
            return gnn   # not enough data for meaningful update

        # Build mini-batch: node feature vectors + binary labels (led_to_finding)
        # For each training step:
        #   forward pass → policy logits
        #   loss = binary cross-entropy(logits, labels)
        #   gradient: approximate with finite differences (no autograd needed with numpy)
        #   W1 -= lr * grad_W1; W2 -= lr * grad_W2
        # Clip gradients to norm 1.0 to prevent divergence
        # Save updated weights
        return gnn

Part C — Attack win rate tracker (extend core/attack_selector.py or create it)
class AttackSelector:
    """
    Ranks attack strategies by historical win rate from OutcomeDB.
    Used by validators to select which payload type to try first.
    """
    def __init__(self, db: OutcomeDB):
        self.db = db

    def rank_payloads(self, vuln_class: str, tech_stack: str,
                      waf_detected: str) -> list[str]:
        """
        Returns ordered list of payload strategy IDs for the vuln_class.
        Highest win rate for this (tech_stack, waf) combination goes first.
        Falls back to alphabetical order if no data available.
        """

    def record_attempt(self, strategy_id: str, tech_stack: str,
                       waf: str, success: bool):
        self.db.update_win_rate(strategy_id, tech_stack, waf, success)

Part D — Wire everything into orchestrator
In core/orchestrator.py:
1. __init__: create OutcomeDB, PostScanFineTuner, AttackSelector
2. After each confirmed finding: db.record_finding(finding, scan_id)
3. After each node validated: db.record_node_decision(...)
4. After scan completes: asyncio.create_task(fine_tuner.fine_tune(gnn, scan_id, db))
   (fire-and-forget — doesn't block scan completion)
5. Pass attack_selector to state dict so validators can use win rates

Part E — False positive feedback CLI (scripts/label_findings.py)
python scripts/label_findings.py --scan-id {id} --finding-id {id} --label fp
This labels a finding as a false positive in OutcomeDB so the fine-tuner
learns to down-weight that node type in future scans.

Part F — Tests (tests/test_outcome_db.py, tests/test_fine_tuner.py)
- Test OutcomeDB.record_scan + record_finding → queryable immediately
- Test update_win_rate: strategy "time_based_sqli", tech "rails" → 3 successes/5 attempts
- Test get_training_data returns correct node-level data
- Test PostScanFineTuner: GNN weights change after fine-tuning on labeled data
- Test weights saved correctly (load and verify changed)

ACCEPTANCE CRITERIA:
- tests/test_outcome_db.py tests/test_fine_tuner.py → all pass
- data/outcomes.db created and queryable after a scan run
- Fine-tuner changes GNN weights (verified by comparing numpy array checksums)
- AttackSelector.rank_payloads returns different order before/after win rate data
- False positive labeling works via CLI
- Zero regression in existing tests
```

---

# SESSION 10 — Integration, Polish, and Full End-to-End Test
**Time estimate:** 3–4 hours
**Depends on:** Sessions 1–9 complete

```
TASK: Wire all sessions together, fix integration bugs, add missing imports,
write the full end-to-end test, and verify the tool works as a complete product.

FIRST read these files:
1. core/orchestrator.py — check all new components are wired in
2. main.py — verify CLI arguments are complete
3. CLAUDE.md — review all components that should be integrated
4. Run: python -m pytest tests/ [standard ignore flags] — fix any new failures

INTEGRATION CHECKLIST — verify each item is working:

[ ] OOB canary starts on orchestrator init, stops on completion
[ ] OOB canary URL passed through state dict to all validators
[ ] GNN weights file created at core/gnn_weights.npz after first scan
[ ] MCTS planner used for validation ordering (log message confirms it)
[ ] Behavioral baseline runs during recon phase for any multi-step URLs
[ ] Traffic normalization active for all HTTP requests from validators
[ ] Payload genetic engine triggered when standard payloads fail (fitness < 0.3)
[ ] ExploitStatePropagator called after every confirmed finding
[ ] Chain candidates dispatched as follow-up validations
[ ] EvidenceStore creates signed bundles in reports/evidence/
[ ] SARIF output written to reports/{scan_id}.sarif
[ ] OutcomeDB records scan + findings + node decisions
[ ] Fine-tuner fires asynchronously after scan completes
[ ] Attack win rates updated after each validation attempt
[ ] GraphQL engine runs when GraphQL endpoint detected
[ ] gRPC engine runs when gRPC service detected
[ ] JWT validator (existing) uses OOB canary for jku/x5u callback detection
[ ] Race condition validator (existing) uses threading.Barrier sync

WHAT TO BUILD IN THIS SESSION:

Part A — Integration audit
Read core/orchestrator.py in full. For any component from Sessions 1–9 that
isn't wired in yet, add the wire-up code. This is the primary task.

Part B — Missing CLI flags (update main.py)
Add these flags if not present:
--oob-host        OOB canary host/IP (default: auto-detect local IP)
--oob-port        OOB canary port (default: 8877)
--profile         Traffic profile: chrome124|firefox124|safari17 (default: chrome124)
--no-normalize    Disable traffic normalization
--no-oob          Disable OOB canary
--label-fp        After scan: label a finding as false positive

Part C — Full integration test (tests/test_integration.py)
Create a mock target server using aiohttp.test_utils:
- Serves 5 endpoints: /, /api/users, /api/users/1, /search?q=test, /graphql
- /search?q=test reflects the q parameter in the response (XSS)
- /api/users/1 returns {"user": "alice", "id": 1}
- /api/users/2 returns {"user": "bob", "id": 2} (IDOR testable)
- /graphql endpoint that reveals schema via introspection

Test: run full orchestrator against this mock server, verify:
- At least one finding confirmed
- Evidence bundle created in reports/evidence/
- SARIF output file created
- OOB canary started and stopped cleanly
- Scan completes in < 120 seconds (mock server is local)

Part D — README update (README.md)
Write a clean README with:
- What the tool does (2-paragraph summary)
- Quick start: pip install requirements, playwright install, python main.py -u target.com
- Full flag reference
- Output files explanation (HTML report, JSON, SARIF, evidence bundles)
- Architecture overview (3-sentence summary of each component)

Part E — Setup script verification (setup.sh)
Verify setup.sh correctly:
- Creates venv
- pip install -r requirements.txt
- playwright install chromium
- pip install sentence-transformers (optional, for embedding reasoner)
- pip install cryptography (for evidence signing)
- Creates data/ and reports/ directories

ACCEPTANCE CRITERIA:
- All 122 original tests still pass
- tests/test_integration.py → all pass (mock server integration)
- Full scan run completes without exception: python main.py -u http://testphp.vulnweb.com
- reports/evidence/ directory populated after scan
- .sarif file created after scan
- data/outcomes.db exists and has rows after scan
- core/gnn_weights.npz exists after scan
- README clearly explains how to run the tool
- No bare except: blocks anywhere in the codebase (grep -r "except:" . to verify)
```

---

## TIPS FOR USING CLAUDE CODE EFFECTIVELY

**Starting each session:**
```
Read CLAUDE.md first, then [paste the session prompt]
```

**If Claude Code loses context mid-session:**
```
Re-read CLAUDE.md and core/orchestrator.py, then continue with:
[paste just the specific Part you were on]
```

**After each session, run:**
```bash
python -m pytest tests/ --ignore=tests/test_api.py \
  --ignore=tests/test_attack_graph.py \
  --ignore=tests/test_crawler.py \
  --ignore=tests/test_osint.py \
  --ignore=tests/test_osint_crtsh.py \
  --ignore=tests/test_phase7.py \
  --ignore=tests/test_priority_queue.py \
  --ignore=tests/test_priority_queue_service.py \
  --ignore=tests/test_redis_dedup.py -q

# Quick smoke test
python main.py -u https://testphp.vulnweb.com --profile auto
```

**If tests break after a session:**
```
Tests were passing before this session. Read the test failures carefully.
Fix only the broken tests without changing the test assertions themselves.
```

**Checking what was built:**
```bash
# Count new lines of code added
git diff --stat HEAD~1

# See new files
git status --short | grep "^?"
```

---

## EXPECTED FINAL STATE

After all 10 sessions, a full scan should:
1. Run OSINT + recon (subfinder, crtsh, httpx, katana, gau)
2. Build an attack graph from discovered endpoints
3. Use GNN + deadline-aware MCTS to prioritize validation order
4. Fire all 14 existing validators + GraphQL + gRPC + BizLogic validators
5. Evolve novel payloads via genetic engine when templates fail
6. Detect blind vulnerabilities via OOB canary
7. Automatically chain SSRF → internal service → credential exposure
8. Capture tamper-evident evidence bundles
9. Output SARIF 2.1 + HTML + JSON reports
10. Update GNN weights for the next scan against this target type

Total code added across 10 sessions: ~4,000–6,000 lines
Total scan capability: finds what commercial scanners miss
Time per scan: 8–20 minutes depending on target size
