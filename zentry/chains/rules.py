"""
Chaining and CVE-to-Validator Rules for the DAG Chain Engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ValidatorSpec:
    id: str
    name: str
    class_path: str
    description: str
    severity: str = "info"
    priority: int = 0
    keywords: List[str] = field(default_factory=list)
    required_ports: List[int] = field(default_factory=list)
    required_protocols: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class VulnerabilitySpec:
    id: str
    title: str
    description: str
    severity: str = "info"
    keywords: List[str] = field(default_factory=list)


DEFAULT_VALIDATOR_SPECS: List[ValidatorSpec] = [
    ValidatorSpec(
        id="integrity_validator",
        name="IntegrityValidator",
        class_path="validators.integrity.IntegrityValidator",
        description="Checks for insecure deserialization and unsigned package integrity issues.",
        severity="high",
        priority=90,
        keywords=["deserialization", "serialization", "integrity", "signature", "package"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="redis_no_auth",
        name="RedisNoAuthValidator",
        class_path="validators.redis.RedisNoAuthValidator",
        description="Checks whether Redis is reachable on port 6379 without authentication.",
        severity="high",
        priority=100,
        keywords=["redis", "6379", "unauthenticated", "no auth"],
        required_ports=[6379],
    ),
    ValidatorSpec(
        id="ftp_anonymous_login",
        name="FTPAnonymousLoginValidator",
        class_path="validators.ftp.FTPAnonymousLoginValidator",
        description="Checks whether the FTP service allows anonymous login on port 21.",
        severity="high",
        priority=80,
        keywords=["ftp", "21", "anonymous"],
        required_ports=[21],
    ),
    ValidatorSpec(
        id="missing_security_headers",
        name="MissingSecurityHeadersValidator",
        class_path="validators.http.MissingSecurityHeadersValidator",
        description="Checks for missing security headers on HTTP endpoints.",
        severity="info",
        priority=10,
        keywords=["http", "headers", "csp", "x-frame-options"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="injection_validator",
        name="InjectionValidator",
        class_path="validators.injection.InjectionValidator",
        description="Checks for reflected XSS and basic SQL error-based injection signals.",
        severity="high",
        priority=86,
        keywords=["sqli", "xss", "injection", "sql", "query", "search"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="insecure_design_validator",
        name="InsecureDesignValidator",
        class_path="validators.insecure_design.InsecureDesignValidator",
        description="Checks for workflow and state-transition bypass behavior.",
        severity="high",
        priority=84,
        keywords=["workflow", "state", "status", "transition", "design"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="broken_access_control_validator",
        name="BrokenAccessControlValidator",
        class_path="validators.access_control.BrokenAccessControlValidator",
        description="Checks unauthenticated access to sensitive endpoints and direct object access controls.",
        severity="high",
        priority=89,
        keywords=["access control", "idor", "admin", "profile", "account", "forbidden"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="crypto_validator",
        name="CryptoValidator",
        class_path="validators.crypto.CryptoValidator",
        description="Checks for weak TLS versions and sensitive data transmitted over plaintext HTTP.",
        severity="high",
        priority=85,
        keywords=["tls", "ssl", "crypto", "cipher", "http", "cookie", "authorization"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="auth_validator",
        name="AuthValidator",
        class_path="validators.auth.AuthValidator",
        description="Checks login endpoints for rate limiting and insecure remember-me cookie flags.",
        severity="high",
        priority=88,
        keywords=["login", "auth", "rate limit", "remember me", "cookie"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="logging_validator",
        name="LoggingValidator",
        class_path="validators.logging.LoggingValidator",
        description="Performs a passive audit of security headers as an indirect monitoring-hardening indicator.",
        severity="info",
        priority=12,
        keywords=["logging", "monitoring", "headers", "x-content-type-options", "csp"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="security_misconfiguration_validator",
        name="SecurityMisconfigurationValidator",
        class_path="validators.misconfiguration.SecurityMisconfigurationValidator",
        description="Checks insecure HTTP methods, debug leakage, and exposed directory listing indicators.",
        severity="high",
        priority=83,
        keywords=["misconfiguration", "trace", "options", "debug", "directory listing"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="outdated_components_validator",
        name="OutdatedComponentsValidator",
        class_path="validators.components.OutdatedComponentsValidator",
        description="Checks for known CVE indicators and outdated component/version disclosures.",
        severity="high",
        priority=82,
        keywords=["cve", "outdated", "component", "version", "x-powered-by", "server"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="ssrf_validator",
        name="SSRFValidator",
        class_path="validators.ssrf.SSRFValidator",
        description="Attempts loopback fetches through suspected URL parameters to validate SSRF behavior.",
        severity="high",
        priority=87,
        keywords=["ssrf", "url", "uri", "destination", "127.0.0.1", "localhost"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="idor_validator",
        name="IDORValidator",
        class_path="validators.idor.IDORValidator",
        description="Tests for object-level authorization bypass by comparing baseline and tampered IDs.",
        severity="high",
        priority=70,
        keywords=["idor", "insecure direct object reference", "object", "a04"],
        required_protocols=["http"],
    ),
    ValidatorSpec(
        id="insecure_deserialization",
        name="InsecureDeserializationValidator",
        class_path="validators.deserialization.InsecureDeserializationValidator",
        description="Detects serialization signatures and validates potential insecure deserialization via timing probe.",
        severity="high",
        priority=75,
        keywords=["deserialization", "serialized", "Tzo", "rO0", "a08"],
        required_protocols=["http"],
    ),
]

DEFAULT_VULNERABILITY_SPECS: List[VulnerabilitySpec] = [
    VulnerabilitySpec(
        id="redis-no-auth",
        title="Unauthenticated Redis Access",
        description="Redis exposed on 6379 and accepting unauthenticated connections.",
        severity="high",
        keywords=["redis", "6379", "auth"],
    ),
    VulnerabilitySpec(
        id="missing-security-headers",
        title="Missing Security Headers",
        description="HTTP response missing baseline defensive headers.",
        severity="info",
        keywords=["headers", "csp", "x-frame-options", "http"],
    ),
]


def get_default_validator_specs() -> List[ValidatorSpec]:
    return list(DEFAULT_VALIDATOR_SPECS)


def get_default_vulnerability_specs() -> List[VulnerabilitySpec]:
    return list(DEFAULT_VULNERABILITY_SPECS)


def extract_keywords(value: Any) -> List[str]:
    keywords: List[str] = []
    if isinstance(value, str):
        keywords.append(value.lower())
    elif isinstance(value, dict):
        for item in value.values():
            keywords.extend(extract_keywords(item))
    elif isinstance(value, list):
        for item in value:
            keywords.extend(extract_keywords(item))
    elif value is not None:
        keywords.append(str(value).lower())
    return keywords


# ── CHAIN_RULES — consumed by ChainEngine.evaluate() ────────────────────────
# Each rule defines a multi-step attack chain that requires specific
# vulnerability types to be present in the findings.
CHAIN_RULES = [
    {
        "chain_id": "chain-001",
        "name": "CSRF → Account Takeover",
        "description": (
            "Missing CSRF protections allow an attacker to perform state-changing "
            "actions on behalf of an authenticated user, escalating to account takeover "
            "when combined with open redirect or XSS."
        ),
        "required_vulns": ["csrf-missing-protections", "open-redirect"],
        "owasp": "A01: Broken Access Control",
    },
    {
        "chain_id": "chain-002",
        "name": "Open Redirect → Phishing → Credential Theft",
        "description": (
            "An open redirect on the target domain enables an attacker to craft "
            "convincing phishing URLs that redirect victims to a credential-harvesting "
            "page hosted on an external domain."
        ),
        "required_vulns": ["open-redirect"],
        "owasp": "A01: Broken Access Control",
    },
    {
        "chain_id": "chain-003",
        "name": "SQLi → Data Exfiltration → Lateral Movement",
        "description": (
            "SQL injection allows extraction of database credentials and sensitive "
            "data. Combined with sensitive file exposure, this enables lateral "
            "movement across the target infrastructure."
        ),
        "required_vulns": ["sql-injection", "sensitive-file-exposure"],
        "owasp": "A03: Injection",
    },
    {
        "chain_id": "chain-004",
        "name": "Default Creds → Authenticated IDOR → Data Breach",
        "description": (
            "Default credentials grant initial access. Combined with IDOR "
            "vulnerabilities, an attacker can enumerate and access other users' "
            "accounts and sensitive data."
        ),
        "required_vulns": ["default-credentials", "idor"],
        "owasp": "A07: Identification and Authentication Failures",
    },
]

# Chaining rules: simple representation of horizontal and vertical chaining
CHAINING_RULES = {
    "git_directory_found": [
        {
            "action": "git_extractor",
            "produces": ["credentials", "paths"],
            "next_if": {"credentials": "ssh_brute"},
        },
    ],
    "lfi_detected": [
        {
            "action": "config_reader",
            "produces": ["secrets", "files"],
            "next_if": {"secrets": "credential_parsing"},
        },
    ],
    "credentials_found": [
        {"action": "ssh_brute", "produces": ["valid_creds", "loot"]},
    ],
}


def get_chaining_for_trigger(trigger: str):
    return CHAINING_RULES.get(trigger, [])


def detect_triggers_from_findings(findings: List[dict]) -> List[str]:
    triggers: List[str] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        title = (f.get("title") or "").lower()
        if ".git" in title or ("git" in title and ("directory" in title or "exposed" in title)):
            triggers.append("git_directory_found")
        if "lfi" in title or "local file" in title:
            triggers.append("lfi_detected")
        if "password" in title or "credentials" in title or "aws_access_key" in title:
            triggers.append("credentials_found")

    return sorted(set(triggers))


@dataclass(frozen=True)
class CVESpec:
    cve_id: str
    title: str
    description: str
    severity: str
    applicable_validators: List[str]
    keywords: List[str] = None


REDIS_CVE_SPECS: List[CVESpec] = [
    CVESpec(
        cve_id="CVE-2025-46817",
        title="Redis < 8.2.1 lua script - Integer Overflow",
        description="Authenticated user can use specially crafted Lua script to cause integer overflow and RCE",
        severity="critical",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "integer overflow", "rce", "8.2.1"],
    ),
    CVESpec(
        cve_id="CVE-2025-49844",
        title="Redis Lua Parser < 8.2.2 - Use After Free",
        description="Authenticated user can manipulate garbage collector via crafted Lua scripts for RCE",
        severity="critical",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "use after free", "rce", "8.2.2"],
    ),
    CVESpec(
        cve_id="CVE-2025-46819",
        title="Redis < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read",
        description="Authenticated user can read out-of-bounds data or crash server via Lua scripts",
        severity="high",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "out of bounds", "dos", "8.2.1"],
    ),
    CVESpec(
        cve_id="CVE-2025-46818",
        title="Redis Lua Sandbox < 8.2.2 - Cross-User Escape",
        description="Authenticated user can escape Lua sandbox and run code in context of another user",
        severity="high",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "sandbox escape", "privilege escalation", "8.2.2"],
    ),
]

ALL_CVE_SPECS: List[CVESpec] = list(REDIS_CVE_SPECS)
ALL_CVE_SPECS.append(
    CVESpec(
        cve_id="CVE-2026-0001",
        title="OpenSSL vulnerable heartbeat overflow",
        description="Heartbeat implementation allows out-of-bounds read leading to data leakage",
        severity="high",
        applicable_validators=["openssl_heartbeat_check"],
        keywords=["openssl", "heartbeat", "heartbleed", "tls"],
    )
)


def get_cve_specs() -> Dict[str, CVESpec]:
    return {spec.cve_id: spec for spec in ALL_CVE_SPECS}


def extract_cve_ids(finding: Dict[str, Any]) -> List[str]:
    cve_ids = []
    if "cve" in finding:
        cves = finding.get("cve")
        if isinstance(cves, list):
            cve_ids.extend([c for c in cves if isinstance(c, str) and c.startswith("CVE-")])
        elif isinstance(cves, str) and cves.startswith("CVE-"):
            cve_ids.append(cves)
    
    title = finding.get("title", "").upper()
    for spec in ALL_CVE_SPECS:
        if spec.cve_id in title:
            cve_ids.append(spec.cve_id)
    
    return list(set(cve_ids))


def find_applicable_validators(cve_id: str) -> List[str]:
    cve_specs = get_cve_specs()
    cve_spec = cve_specs.get(cve_id)
    if cve_spec:
        return cve_spec.applicable_validators
    return []


def get_cve_info(cve_id: str) -> Optional[CVESpec]:
    return get_cve_specs().get(cve_id)


class CVEMapper:
    def __init__(self):
        self.cve_specs = get_cve_specs()
    
    def map_findings_to_cves(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        cve_to_validators: Dict[str, List[str]] = {}
        for finding in findings:
            cve_ids = extract_cve_ids(finding)
            for cve_id in cve_ids:
                if cve_id in self.cve_specs:
                    validators = self.cve_specs[cve_id].applicable_validators
                    if cve_id not in cve_to_validators:
                        cve_to_validators[cve_id] = []
                    cve_to_validators[cve_id].extend(validators)
        
        for cve_id in cve_to_validators:
            cve_to_validators[cve_id] = list(set(cve_to_validators[cve_id]))
        return cve_to_validators
    
    def get_cve_verdict_data(self, cve_id: str) -> Dict[str, Any]:
        spec = self.cve_specs.get(cve_id)
        if spec:
            return {
                "cve_id": spec.cve_id,
                "title": spec.title,
                "description": spec.description,
                "severity": spec.severity,
            }
        return {
            "cve_id": cve_id,
            "title": "Unknown CVE",
            "description": "",
            "severity": "unknown",
        }
