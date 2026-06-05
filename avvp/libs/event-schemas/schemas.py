from dataclasses import dataclass, asdict, field
from typing import Dict, Any, ClassVar
from datetime import datetime
import json
import jsonschema

BASE_EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "scan_id": {"type": "string"},
        "timestamp": {"type": "string"},
        "schema_version": {"type": "string"},
        "payload": {"type": "object"}
    },
    "required": ["scan_id", "timestamp", "schema_version", "payload"]
}

@dataclass
class BaseEvent:
    scan_id: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    schema_version: ClassVar[str] = "1.0"
    payload: Dict[str, Any] = field(default_factory=dict)
    topic: ClassVar[str] = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["schema_version"] = self.schema_version
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def validate_dict(cls, d: Dict[str, Any]):
        jsonschema.validate(instance=d, schema=BASE_EVENT_SCHEMA)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]):
        cls.validate_dict(d)
        return cls(scan_id=d["scan_id"], timestamp=d.get("timestamp"), payload=d.get("payload", {}))


# Define required event types
@dataclass
class SurfaceSeedEvent(BaseEvent):
    topic: ClassVar[str] = "surface.seed"

@dataclass
class ReconRawEvent(BaseEvent):
    topic: ClassVar[str] = "recon.raw"

@dataclass
class ReconDedupedEvent(BaseEvent):
    topic: ClassVar[str] = "recon.deduped"

@dataclass
class ReconNormalizedEvent(BaseEvent):
    topic: ClassVar[str] = "recon.normalized"

@dataclass
class GraphUpdatedEvent(BaseEvent):
    topic: ClassVar[str] = "graph.updated"

@dataclass
class GraphReadyEvent(BaseEvent):
    topic: ClassVar[str] = "graph.ready"

@dataclass
class AttackPlanEvent(BaseEvent):
    topic: ClassVar[str] = "attack.plan"

@dataclass
class ValidationJobEvent(BaseEvent):
    topic: ClassVar[str] = "validation.job"

@dataclass
class ValidationResultEvent(BaseEvent):
    topic: ClassVar[str] = "validation.result"

@dataclass
class FindingConfirmedEvent(BaseEvent):
    topic: ClassVar[str] = "finding.confirmed"

@dataclass
class ChainLinkEvent(BaseEvent):
    topic: ClassVar[str] = "chain.link"

@dataclass
class EvidenceSealedEvent(BaseEvent):
    topic: ClassVar[str] = "evidence.sealed"

# Helper utilities
def event_from_json(topic: str, payload_json: str) -> BaseEvent:
    d = json.loads(payload_json)
    mapping = {
        SurfaceSeedEvent.topic: SurfaceSeedEvent,
        ReconRawEvent.topic: ReconRawEvent,
        ReconDedupedEvent.topic: ReconDedupedEvent,
        ReconNormalizedEvent.topic: ReconNormalizedEvent,
        GraphUpdatedEvent.topic: GraphUpdatedEvent,
        GraphReadyEvent.topic: GraphReadyEvent,
        AttackPlanEvent.topic: AttackPlanEvent,
        ValidationJobEvent.topic: ValidationJobEvent,
        ValidationResultEvent.topic: ValidationResultEvent,
        FindingConfirmedEvent.topic: FindingConfirmedEvent,
        ChainLinkEvent.topic: ChainLinkEvent,
        EvidenceSealedEvent.topic: EvidenceSealedEvent,
    }
    cls = mapping.get(topic, BaseEvent)
    return cls.from_dict(d)
