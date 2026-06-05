import docker
import asyncio

class AgentManager:
    def __init__(self):
        self.client = docker.from_env()

    async def spawn_agent(self, image: str, env: dict, mem_limit: str = '512m', cpu_quota: int = 50000) -> str:
        container = self.client.containers.run(image, detach=True, environment=env, mem_limit=mem_limit, cpu_quota=cpu_quota)
        return container.id

    def kill_agent(self, container_id: str):
        try:
            cont = self.client.containers.get(container_id)
            cont.kill()
        except Exception:
            pass
