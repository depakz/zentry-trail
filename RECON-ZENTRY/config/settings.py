"""Centralized configuration"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SESSIONS_DIR = BASE_DIR / "data" / "sessions"
PAYLOADS_DIR = BASE_DIR / "payloads"

# Performance
MAX_CONCURRENT_TASKS = 20
HTTP_TIMEOUT = 15
TOOL_TIMEOUT = 300
RETRY_COUNT = 2

# Rate limiting (requests/sec per host)
RATE_LIMIT = 30
NUCLEI_RATE = 150
FFUF_RATE = 50

# Batching
NUCLEI_BATCH_SIZE = 500   # was 50 — removed bottleneck
FFUF_BATCH_SIZE = 100

# Scan controls
SAFE_MODE = True   # avoid destructive payloads
ENABLE_SQLMAP = True
ENABLE_DALFOX = True
ENABLE_FFUF = True
ENABLE_ARJUN = True

# High-value param names (for scoring)
HIGH_VALUE_PARAMS = {
    "id", "user", "uid", "userid", "page", "file", "path", "dir", "folder",
    "url", "redirect", "next", "return", "returnurl", "return_url", "callback",
    "cmd", "exec", "command", "query", "search", "q", "keyword", "name",
    "include", "require", "load", "view", "template", "module", "fn",
    "data", "input", "ref", "src", "dest", "domain", "host", "ip",
    "token", "key", "api_key", "auth", "session", "debug", "test"
}

VULN_KEYWORDS = {
    "sqli": ["id", "user", "uid", "search", "q", "select", "where"],
    "xss": ["search", "q", "name", "comment", "msg", "input", "callback"],
    "ssrf": ["url", "redirect", "callback", "next", "src", "domain", "host", "uri"],
    "lfi": ["file", "path", "page", "include", "load", "view", "template"],
    "openredirect": ["redirect", "url", "next", "return", "returnurl", "dest"],
}

# Tool paths (autodetect via shutil.which)
TOOLS = {
    "subfinder": "subfinder",
    "httpx": "httpx",
    "katana": "katana",
    "gau": "gau",
    "nuclei": "nuclei",
    "ffuf": "ffuf",
    "arjun": "arjun",
    "paramspider": "paramspider",
    "dalfox": "dalfox",
    "sqlmap": "sqlmap",
}

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) HackWithYuva/4.0"
