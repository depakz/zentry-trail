# Zentry Trail: Autonomous Security Testing Pipeline

Zentry is an advanced, AI-driven autonomous security testing framework designed to discover, prioritize, and validate vulnerabilities across modern web applications, APIs, and infrastructure.

## 🚀 Current Status: Active Development

The platform has recently integrated advanced execution engines for GraphQL, gRPC, and dynamic payload generation. It actively uses Graph Neural Networks (GNN) and Monte Carlo Tree Search (MCTS) for intelligent attack prioritization.

## 🛡️ Core Capabilities

### 1. Intelligent Orchestration & Planning
- **MCTS Planner & GNN**: Prioritizes attack graph nodes using a deadline-aware Monte Carlo Tree Search backed by a Graph Neural Network.
- **Behavioral Baseline Engine**: Maps multi-step workflows (e.g., checkout flows) to detect business logic flaws, step skipping, price tampering, and horizontal IDORs.
- **Adaptive Exploit Engine**: Uses a Multi-Armed Bandit algorithm to select the most successful payloads based on historical reward data.

### 2. Advanced Validation Engines
- **Payload Genetic Engine**: Structurally evolves novel attack strings (SQLi, XSS, SSRF) via crossover and mutation when traditional static signatures are blocked by WAFs. Evaluated via the `DifferentialAnalyzer`.
- **GraphQL Attack Engine**: Extracts schemas without introspection via typo-suggestion parsing. Tests for batch query rate-limit bypasses, nested query resource exhaustion (DoS), and object-level IDORs.
- **gRPC Reflection Validator**: Identifies exposed gRPC reflection endpoints and probes for unauthenticated method access using empty protobuf payloads.
- **OOB Canary Server**: Built-in out-of-band server for detecting blind vulnerabilities (e.g., blind SSRF, blind RCE).

### 3. Pipeline Modules
- **Discovery & Recon**: Aggregates targets using `subfinder`, `amass`, `gau`, and `katana`.
- **Context-Aware Validators**: Custom validators for finding XSS, SQLi, SSRF, XXE, Open Redirects, Insecure Deserialization, Broken Access Control, Subdomain Takeovers, and more.
- **Chain Synthesis**: Automatically resolves compatible artifacts (e.g., extracted AWS keys or JWTs) to expand attack chains dynamically.

### 4. Reporting & Integration
- **SARIF Reporter**: Outputs validated findings to SARIF 2.1.0 format, ready for CI/CD, GitHub Code Scanning, and VS Code integration.
- **Evidence Store**: Cryptographically signs and stores HTTP request/response artifacts to guarantee non-repudiation of findings.

## 🧪 Running the Test Suite

The platform maintains a rigorous verification standard. You can run the entire test suite using `pytest`:

```bash
python -m pytest tests/ -v
```

### Selected Test Modules:
- `tests/test_genetic_engine.py` - Verifies payload mutation and differential analysis.
- `tests/test_graphql_engine.py` - Verifies schema inference and deep query attacks.
- `tests/test_grpc_engine.py` - Verifies reflection mapping and unauthenticated probes.
- `tests/test_mcts_planner_v2.py` - Validates the GNN forward passes and MCTS exploration decay.
- `tests/test_behavioral_baseline.py` - Tests state machine deviation probes.

## 🏗️ Next Steps / Roadmap

- **Session 4/5**: Enhancing the Behavioral Baseline Engine for deeper business logic flaw detection (e.g., race conditions, complex RBAC bypasses).
- Expanded integration with specialized third-party exploitation tools.