"""Normalized HTTP Client."""

import asyncio
import aiohttp
from typing import Any, Dict, Optional

from core.traffic_profiles import PROFILES
from core.timing_engine import GaussianTimer, NoiseRequestInjector

class NormalizedHTTPClient:
    def __init__(self, profile_name: str = "chrome124", timer_mode: str = "web"):
        self.profile_name = profile_name
        self.profile = PROFILES.get(profile_name, PROFILES["chrome124"])
        self.timer = GaussianTimer(mode=timer_mode)
        self.injector = NoiseRequestInjector()
        self.session: Optional[aiohttp.ClientSession] = None

    def get_headers(self) -> Dict[str, str]:
        headers = {}
        try:
            for key in self.profile.get("header_order", []):
                if key in self.profile:
                    headers[key] = self.profile[key]
            return headers
        except Exception as e:
            return {"User-Agent": "Mozilla/5.0"}

    async def __aenter__(self):
        try:
            if not self.session or self.session.closed:
                self.session = aiohttp.ClientSession(headers=self.get_headers())
            return self
        except Exception as e:
            self.session = None
            return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.session and not self.session.closed:
                await self.session.close()
        except Exception as e:
            pass

    async def _handle_noise(self, url: str):
        try:
            if self.injector.should_inject() and self.session:
                noise_url = self.injector.get_noise_url(url)
                try:
                    await self.session.get(noise_url, timeout=5)
                except Exception as e:
                    pass
        except Exception as e:
            pass

    def _merge_headers(self, kwargs: Dict[str, Any]) -> None:
        headers = self.get_headers()
        if "headers" in kwargs:
            for k, v in kwargs["headers"].items():
                headers[k] = v
        if "Host" in headers and not headers["Host"]:
            del headers["Host"]
        kwargs["headers"] = headers

    async def get(self, url: str, **kwargs) -> Any:
        try:
            await self.timer.sleep()
            await self._handle_noise(url)
            self._merge_headers(kwargs)
            return await self.session.get(url, **kwargs) if self.session else None
        except Exception as e:
            raise e

    async def post(self, url: str, **kwargs) -> Any:
        try:
            await self.timer.sleep()
            await self._handle_noise(url)
            self._merge_headers(kwargs)
            return await self.session.post(url, **kwargs) if self.session else None
        except Exception as e:
            raise e