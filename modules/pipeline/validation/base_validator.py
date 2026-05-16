"""Validation dispatcher — discards anything not confirmed."""
from modules.pipeline.validation.xss_validator import validate_xss
from modules.pipeline.validation.sqli_validator import validate_sqli
from modules.pipeline.validation.lfi_validator import validate_lfi
from modules.pipeline.validation.ssrf_validator import validate_ssrf

VALIDATORS = {
    "xss": validate_xss,
    "sqli": validate_sqli,
    "lfi": validate_lfi,
    "ssrf": validate_ssrf,
}

async def validate(vuln_type: str, url: str, param: str):
    fn = VALIDATORS.get(vuln_type)
    if not fn:
        return None
    try:
        return await fn(url, param)
    except Exception as e:
        return None  # Failure = no finding (no FP rule)
