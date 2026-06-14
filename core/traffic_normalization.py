"""Traffic normalization to evade WAF detection via browser profile mimicry."""

import time
import random
from typing import Dict, Optional


BROWSER_PROFILES = {
    "chrome124": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "connection": "keep-alive",
    },
    "firefox124": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "connection": "keep-alive",
    },
    "safari17": {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "connection": "keep-alive",
    },
}


class GaussianTimer:
    """Inter-request delays drawn from Gaussian distribution."""

    def __init__(self):
        self.last_request = time.time()

    def wait(self, mode: str = "browse") -> None:
        """Sleep for delay, then update last_request timestamp."""
        if mode == "browse":
            # N(mean=800ms, sigma=400ms) for page browsing
            delay = max(0.05, min(5.0, random.gauss(0.8, 0.4)))
        else:
            # N(mean=80ms, sigma=20ms) for API calls
            delay = max(0.05, min(5.0, random.gauss(0.08, 0.02)))

        time.sleep(delay)
        self.last_request = time.time()

    def should_inject_noise_request(self) -> bool:
        """Return True with 8% probability."""
        return random.random() < 0.08


class NormalizedHTTPClient:
    """HTTP client that mimics real browser traffic."""

    def __init__(self, profile_name: str = "chrome124"):
        self.profile = BROWSER_PROFILES.get(profile_name, BROWSER_PROFILES["chrome124"])
        self.timer = GaussianTimer()

    def get_headers(self) -> Dict[str, str]:
        """Get normalized headers for this profile."""
        return {
            "User-Agent": self.profile["user_agent"],
            "Accept": self.profile["accept"],
            "Accept-Language": self.profile["accept_language"],
            "Accept-Encoding": self.profile["accept_encoding"],
            "Connection": self.profile["connection"],
        }

    def wait_before_request(self, is_api: bool = False) -> None:
        """Wait with Gaussian timing before firing request."""
        self.timer.wait(mode="api" if is_api else "browse")
