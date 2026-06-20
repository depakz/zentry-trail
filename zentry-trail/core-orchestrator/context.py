import asyncio
from collections import defaultdict
from typing import Set, Dict, List, Any, Optional
import threading

class Context:
    def __init__(self):
        self.alive_hosts: Set[str] = set()
        self.tech_stacks: Dict[str, List[str]] = defaultdict(list)
        self.asset_queue = asyncio.Queue()
        self.results_lock = threading.Lock()
        self.results: List[Dict[str, Any]] = []
        self.active_tasks = set()
        self.shutdown_event = asyncio.Event()

    async def add_alive_host(self, host: str):
        self.alive_hosts.add(host)
        
    def add_tech_stack(self, host: str, tech: str):
        self.tech_stacks[host].append(tech)
        
    async def enqueue_asset(self, asset: str):
        await self.asset_queue.put(asset)
        
    async def dequeue_asset(self) -> str:
        return await self.asset_queue.get()
        
    def add_result(self, result: Dict[str, Any]):
        with self.results_lock:
            self.results.append(result)
            
    def register_task(self, task: asyncio.Task):
        self.active_tasks.add(task)
        task.add_done_callback(lambda t: self.active_tasks.remove(t))
        
    async def graceful_shutdown(self):
        self.shutdown_event.set()
        await asyncio.gather(*self.active_tasks, return_exceptions=True)