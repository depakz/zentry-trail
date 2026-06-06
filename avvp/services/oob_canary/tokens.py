"""
Token generation and management for OOB canary callbacks.

Generates URL-safe tokens in format: /{scan_id}/{finding_id}/{random_suffix}
Provides utility to construct callback URLs.
"""

import secrets
import string
from typing import Optional


def generate_token(scan_id: str, finding_id: str) -> str:
    """
    Generate a URL-safe OOB callback token.

    Format: {scan_id}_{finding_id}_{12_random_chars}
    Example: abc123_vuln_999_xyzabc1234567

    Args:
        scan_id: Unique scan identifier
        finding_id: Unique finding identifier within the scan

    Returns:
        URL-safe token string
    """
    # Generate 12 random URL-safe characters
    random_suffix = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(12)
    )
    token = f"{scan_id}_{finding_id}_{random_suffix}"
    return token


def get_canary_url(token: str, base_url: str) -> str:
    """
    Construct the full callback URL for a token.

    Args:
        token: Generated token from generate_token()
        base_url: Base URL of OOB server (e.g., http://attacker.com:8877)

    Returns:
        Full callback URL (e.g., http://attacker.com:8877/token)
    """
    # Ensure base_url doesn't have trailing slash
    base_url = base_url.rstrip("/")
    # Ensure token doesn't have leading slash
    token = token.lstrip("/")
    return f"{base_url}/{token}"


def parse_token(token: str) -> Optional[dict]:
    """
    Parse a token to extract scan_id and finding_id.

    Args:
        token: Token string (e.g., abc123_vuln_999_xyzabc1234567)

    Returns:
        Dict with {scan_id, finding_id, random} or None if invalid
    """
    parts = token.split("_")
    if len(parts) < 3:
        return None

    # Last part is random suffix, first two are scan_id and finding_id
    scan_id = parts[0]
    finding_id = parts[1]
    random_suffix = "_".join(parts[2:])

    # Validate that we have actual scan_id and finding_id (not just split on underscore)
    if not scan_id or not finding_id or len(random_suffix) < 10:
        return None

    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "random": random_suffix,
    }
