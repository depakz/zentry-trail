import json
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from avvp.libs.event_schemas.schemas import ValidationJobEvent, FindingConfirmedEvent

class Tier2Agent:
    def __init__(self, bootstrap: str = "localhost:9092", group_id: str = "tier2"):
        self.consumer = AIOKafkaConsumer("validation.job", bootstrap_servers=bootstrap, group_id=group_id)
        self.producer = AIOKafkaProducer(bootstrap_servers=bootstrap)

    async def start(self):
        await self.consumer.start()
        await self.producer.start()
        async for msg in self.consumer:
            payload = json.loads(msg.value.decode())
            job = ValidationJobEvent.from_dict(payload)
            await self.handle_job(job)

    async def handle_job(self, job: ValidationJobEvent):
        # deeper checks: re-run validator variants; if confirmed emit FindingConfirmedEvent
        confirmed = job.payload.get('confirmed', False)
        if confirmed:
            event = FindingConfirmedEvent(scan_id=job.scan_id, payload={**job.payload, 'finding_id': 'fc-' + job.scan_id})
            await self.producer.send_and_wait(event.topic, json.dumps(event.to_dict()).encode())
