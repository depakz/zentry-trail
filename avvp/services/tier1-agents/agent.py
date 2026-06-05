import asyncio
import shutil
import json
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from avvp.libs.event_schemas.schemas import ValidationResultEvent, ValidationJobEvent

class Tier1Agent:
    def __init__(self, bootstrap: str = "localhost:9092", group_id: str = "tier1"):
        self.bootstrap = bootstrap
        self.group_id = group_id
        self.consumer = AIOKafkaConsumer("validation.job", bootstrap_servers=bootstrap, group_id=group_id)
        self.producer = AIOKafkaProducer(bootstrap_servers=bootstrap)

    async def start(self):
        await self.consumer.start()
        await self.producer.start()
        asyncio.create_task(self._loop())

    async def stop(self):
        await self.consumer.stop()
        await self.producer.stop()

    async def _loop(self):
        async for msg in self.consumer:
            try:
                payload = json.loads(msg.value.decode())
                job = ValidationJobEvent.from_dict(payload)
                await self.handle_job(job)
            except Exception:
                continue

    async def handle_job(self, job: ValidationJobEvent):
        # For prototype, run dalfox for XSS or nuclei for other templates based on job.payload
        vuln_type = job.payload.get("vuln_class")
        target = job.payload.get("target")
        result = {"confirmed": False, "evidence": {}, "poc_payload": None}
        # run a lightweight local check: if vuln_type == 'XSS' and 'script' in target -> confirmed
        if vuln_type == 'XSS' and 'script' in (target or ""):
            result['confirmed'] = True
            result['evidence'] = {"note": "heuristic match"}
        # publish result
        event = ValidationResultEvent(scan_id=job.scan_id, payload={**job.payload, **result})
        await self.producer.send_and_wait(event.topic, json.dumps(event.to_dict()).encode())
