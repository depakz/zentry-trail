"""
Out-of-Band (OOB) Canary Server & Tokens — detects blind SSRF, SQLi, RCE via callback detection.
Lightweight aiohttp server.
"""

import asyncio
import time
import secrets
import string
from dataclasses import dataclass, field
from typing import Dict, Optional, Any
from datetime import datetime

from aiohttp import web
from rich.console import Console

console = Console()


# ── Token Generation & Parsing ────────────────────────────────────────────────

def generate_token(scan_id: str, finding_id: str) -> str:
    """
    Generate a URL-safe OOB callback token.
    Format: {scan_id}_{finding_id}_{12_random_chars}
    """
    random_suffix = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(12)
    )
    token = f"{scan_id}_{finding_id}_{random_suffix}"
    return token


def get_canary_url(token: str, base_url: str) -> str:
    """Construct the full callback URL for a token."""
    base_url = base_url.rstrip("/")
    token = token.lstrip("/")
    return f"{base_url}/{token}"


def parse_token(token: str) -> Optional[dict]:
    """Parse a token to extract scan_id and finding_id."""
    parts = token.split("_")
    if len(parts) < 3:
        return None

    scan_id = parts[0]
    finding_id = parts[1]
    random_suffix = "_".join(parts[2:])

    if not scan_id or not finding_id or len(random_suffix) < 10:
        return None

    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "random": random_suffix,
    }


# ── Callback & Server ─────────────────────────────────────────────────────────

@dataclass
class Callback:
    """Represents an OOB callback received from target."""
    token: str
    timestamp: float
    source_ip: str
    method: str
    path: str
    query_string: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "headers": self.headers,
            "body": self.body,
        }


class OOBCanaryServer:
    """
    Standalone OOB canary server for blind vulnerability detection.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8877):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.callbacks: Dict[str, Callback] = {}
        self.app.router.add_get("/{path_info:.+}", self._handle_request)
        self.app.router.add_post("/{path_info:.+}", self._handle_request)
        self.app.router.add_get("/check/{token}", self._check_token)
        self.runner = None
        self.site = None

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Handle any incoming request and store callback."""
        path = request.path
        source_ip = request.remote or "unknown"

        # Extract token from path: /token or /scan_id/finding_id/random
        parts = [p for p in path.split("/") if p]
        token = parts[0] if parts else "unknown"

        headers_dict = dict(request.headers)
        try:
            body = await request.text()
        except Exception:
            body = ""

        callback = Callback(
            token=token,
            timestamp=time.time(),
            source_ip=source_ip,
            method=request.method,
            path=path,
            query_string=request.query_string or "",
            headers=headers_dict,
            body=body[:500],
        )

        self.callbacks[token] = callback
        console.log(
            f"[yellow]🔔 OOB Callback received[/] token={token} source={source_ip} method={request.method} path={path}"
        )

        return web.Response(text="OK", status=200)

    async def _check_token(self, request: web.Request) -> web.Response:
        """GET /check/{token} — returns whether callback was received."""
        token = request.match_info.get("token", "")

        if not token:
            return web.json_response({"found": False, "token": ""}, status=400)

        found = token in self.callbacks
        result = {
            "found": found,
            "token": token,
        }

        if found:
            result["callback"] = self.callbacks[token].to_dict()

        return web.json_response(result, status=200)

    async def start(self) -> None:
        """Start the OOB server."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        console.log(
            f"[green]✓ OOB Canary server started[/] on {self.host}:{self.port}"
        )

    async def stop(self) -> None:
        """Stop the OOB server cleanly."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        console.log("[green]✓ OOB Canary server stopped[/]")

    def get_callback(self, token: str) -> Optional[Callback]:
        """Retrieve a callback by token."""
        return self.callbacks.get(token)

    def has_callback(self, token: str) -> bool:
        """Check if a callback was received for a token."""
        return token in self.callbacks

    def clear(self) -> None:
        """Clear all stored callbacks (useful for testing)."""
        self.callbacks.clear()


# Global OOBCanary singleton
_oob_instance: Optional[OOBCanaryServer] = None


def get_oob_server(host: str = "0.0.0.0", port: int = 8877) -> OOBCanaryServer:
    """Get or create the OOB canary server singleton."""
    global _oob_instance
    if _oob_instance is None:
        _oob_instance = OOBCanaryServer(host=host, port=port)
    return _oob_instance


async def start_oob_server(host: str = "0.0.0.0", port: int = 8877) -> OOBCanaryServer:
    """Start the OOB canary server and return it."""
    server = get_oob_server(host=host, port=port)
    await server.start()
    return server


async def stop_oob_server() -> None:
    """Stop the global OOB server."""
    global _oob_instance
    if _oob_instance:
        await _oob_instance.stop()
        _oob_instance = None
