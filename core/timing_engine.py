"""Timing Engine & Artificial Telemetry Noise."""

import random
import asyncio

class GaussianTimer:
    def __init__(self, mode: str = "web"):
        self.mode = mode

    def get_delay(self) -> float:
        try:
            if self.mode == "api":
                mu, sigma = 80.0, 20.0
                floor, ceiling = 10.0, 1000.0
            else:
                mu, sigma = 800.0, 400.0
                floor, ceiling = 50.0, 5000.0

            delay = random.gauss(mu, sigma)
            return max(floor, min(ceiling, delay)) / 1000.0
        except Exception as e:
            return 0.8

    async def sleep(self):
        try:
            await asyncio.sleep(self.get_delay())
        except Exception as e:
            pass

class NoiseRequestInjector:
    def __init__(self, probability: float = 0.08):
        self.probability = probability
        self.assets = ["/favicon.ico", "/robots.txt", "/assets/logo.png", "/css/main.css", "/js/app.js"]

    def should_inject(self) -> bool:
        try:
            return random.random() < self.probability
        except Exception as e:
            return False

    def get_noise_url(self, base_url: str) -> str:
        try:
            from urllib.parse import urljoin
            return urljoin(base_url, random.choice(self.assets))
        except Exception as e:
            return base_url + "/favicon.ico"