"""Retry tier configuration. Each tier is progressively slower & stealthier."""
from dataclasses import dataclass

@dataclass
class ProbeTier:
    name: str
    rate_limit: int
    threads: int
    timeout: int
    retries: int
    extra_flags: str
    description: str


TIER_FAST = ProbeTier(
    name="tier-1-fast",
    rate_limit=150,
    threads=50,
    timeout=10,
    retries=2,
    extra_flags="-random-agent",
    description="Default fast scan",
)

TIER_SAFE = ProbeTier(
    name="tier-2-safe",
    rate_limit=30,
    threads=10,
    timeout=20,
    retries=3,
    extra_flags=(
        "-random-agent "
        '-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" '
        '-H "Accept-Language: en-US,en;q=0.5" '
        '-H "Cache-Control: no-cache"'
    ),
    description="Stealth mode with browser-like headers",
)

TIER_DEEP = ProbeTier(
    name="tier-3-deep",
    rate_limit=10,
    threads=5,
    timeout=30,
    retries=4,
    extra_flags=(
        "-random-agent -no-fallback-scheme "
        '-H "Accept: */*" '
        '-H "Connection: keep-alive"'
    ),
    description="HTTPS-only, slow & deep fallback",
)

ALL_TIERS = [TIER_FAST, TIER_SAFE, TIER_DEEP]
