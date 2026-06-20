import asyncio
from aiohttp import web
from datetime import datetime
from rich.console import Console
from typing import Dict, Any

console = Console()

class OOBCanaryServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8877):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.callbacks: Dict[str, Dict[str, Any]] = {}
        self._setup_routes()
        
    def _setup_routes(self):
        self.app.router.add_get('/{tail:.*}', self._catch_all)
        self.app.router.add_get('/check/{token}', self._check_callback)
        
    async def _catch_all(self, request):
        # Extract token from path: /{scan_id}/{finding_id}/{random_chars}
        # But we only care about the token (last part) for storage
        path = request.path
        method = request.method
        source_ip = request.remote
        
        # The token is the last non-empty segment
        parts = [p for p in path.split('/') if p]
        if not parts:
            return web.Response(text="Not Found", status=404)
            
        token = parts[-1]  # Use the last part as token
        
        # Store callback
        self.callbacks[token] = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': source_ip,
            'method': method,
            'path': path
        }
        
        console.log(f"[OOB Canary] Callback received for token: {token} from {source_ip}")
        return web.Response(text="OK", status=200)
        
    async def _check_callback(self, request):
        token = request.match_info['token']
        callback = self.callbacks.get(token)
        if callback:
            return web.json_response({'found': True, 'callback': callback})
        else:
            return web.json_response({'found': False})
            
    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        console.log(f"[OOB Canary] Server started on http://{self.host}:{self.port}")
        return runner
        
    async def stop(self, runner):
        await runner.cleanup()
        console.log("[OOB Canary] Server stopped")

# Global server instance and runner for lifecycle management
_server_instance = None
_runner = None

async def start_canary_server(host: str = "0.0.0.0", port: int = 8877) -> str:
    global _server_instance, _runner
    _server_instance = OOBCanaryServer(host, port)
    _runner = await _server_instance.start()
    return f"http://{host}:{port}"

async def stop_canary_server():
    global _server_instance, _runner
    if _runner and _server_instance:
        await _server_instance.stop(_runner)
        _server_instance = None
        _runner = None

def get_callbacks() -> Dict[str, Dict[str, Any]]:
    if _server_instance:
        return _server_instance.callbacks
    return {}
        
if __name__ == "__main__":
    # For direct execution
    async def main():
        runner = await start_canary_server()
        try:
            while True:
                await asyncio.sleep(3600)  # Keep running
        except KeyboardInterrupt:
            pass
        finally:
            await stop_canary_server()
    
    asyncio.run(main())