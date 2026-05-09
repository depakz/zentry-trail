"""Validation dispatcher — discards anything not confirmed."""
from validation.xss_validator import validate_xss
from validation.sqli_validator import validate_sqli

VALIDATORS = {
    "xss": validate_xss,
    "sqli": validate_sqli,
}

async def validate(vuln_type: str, url: str, param: str):
    fn = VALIDATORS.get(vuln_type)
    if not fn:
        return None
    try:
        return await fn(url, param)
    except Exception as e:
        return None  # Failure = no finding (no FP rule)
