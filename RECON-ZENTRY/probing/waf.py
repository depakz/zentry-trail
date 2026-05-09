"""WAF detection: header-based + wafw00f fallback (ANSI-clean)."""
import re
import shutil
from utils.runner import run_cmd

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

WAF_SIGNATURES = {
    "cloudflare":   ["cf-ray", "cf-cache-status", "__cfduid", "__cf_bm"],
    "akamai":       ["akamai-x-cache", "akamaighost", "ak_bmsc"],
    "aws_waf":      ["x-amzn-requestid", "x-amz-cf-id", "awsalb", "awsalbcors"],
    "imperva":      ["x-iinfo", "incap_ses", "visid_incap"],
    "sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
    "f5_bigip":     ["bigipserver", "f5-"],
    "fastly":       ["fastly-debug", "x-served-by"],
    "barracuda":    ["barra_counter_session"],
    "fortinet":     ["fortiwafsid"],
}


def _clean(text: str) -> str:
    """Strip ANSI color codes and extra whitespace."""
    return ANSI_RE.sub('', text).strip()


def detect_from_response(headers: dict, cookies: str = "") -> str:
    blob = " ".join([f"{k.lower()}={v}" for k, v in headers.items()]) + " " + cookies.lower()
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in blob:
                return waf
    return "none"


async def detect_with_wafw00f(url: str, timeout: int = 60) -> str:
    if not shutil.which("wafw00f"):
        return "wafw00f-not-installed"
    code, out, _ = await run_cmd(f"wafw00f -a -o /dev/null {url}", timeout=timeout)
    out = _clean(out)
    for line in out.splitlines():
        low = line.lower()
        if "is behind" in low:
            # Extract WAF name cleanly
            after = line.split("behind", 1)[-1]
            return _clean(after).strip(" .[]()")
        if "no waf detected" in low or "generic" in low:
            return "none"
    return "unknown"
