CHAIN_RULES = [
    {
        "id": "chain-001",
        "name": "XSS via Open Redirect",
        "description": "Attacker abuses Open Redirect on same host to bypass CSP and deliver XSS payload to victim",
        "severity": "critical",
        "requires": ["open-redirect", "reflected-xss"],
        "same_host": True,
        "owasp": "A03",
        "cvss_boost": 0.3
    },
    {
        "id": "chain-002",
        "name": "Admin Panel Access via SQLi + File Leak",
        "description": "SQL Injection combined with sensitive file exposure allows complete database and file system access",
        "severity": "critical",
        "requires": ["sensitive-file-exposure", "sql-injection"],
        "same_host": True,
        "owasp": "A03",
        "cvss_boost": 0.3
    },
    {
        "id": "chain-003",
        "name": "CSRF-Amplified SQLi",
        "description": "A database query can be executed via forced user action due to missing CSRF protection",
        "severity": "high",
        "requires": ["sql-injection", "csrf-missing-protections"],
        "same_host": True,
        "owasp": "A01",
        "cvss_boost": 0.2
    },
    {
        "id": "chain-004",
        "name": "Phishing via Legitimate Domain + Admin Recon",
        "description": "Abusing Open Redirect alongside admin path exposure facilitates highly targeted administrative phishing attacks",
        "severity": "high",
        "requires": ["sensitive-file-exposure", "open-redirect"],
        "filters": {
            "sensitive-file-exposure": {"target_url": "admin"}
        },
        "same_host": True,
        "owasp": "A01",
        "cvss_boost": 0.2
    }
]
