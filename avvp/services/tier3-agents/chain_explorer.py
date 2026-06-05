from typing import List, Dict
from avvp.libs.event_schemas.schemas import ChainLinkEvent, FindingConfirmedEvent

CHAIN_RULES = {
    "SSRF": ["CLOUD_CREDENTIAL_EXPOSURE", "INTERNAL_SERVICE_ACCESS", "RCE"],
    "SQLI": ["DATA_EXFILTRATION", "AUTH_BYPASS", "CREDENTIAL_THEFT"],
    "IDOR": ["PII_EXPOSURE", "PRIVILEGE_ESCALATION", "ACCOUNT_TAKEOVER"],
}

class ChainExplorer:
    def __init__(self, kafka_producer=None):
        self.producer = kafka_producer

    async def explore(self, finding: FindingConfirmedEvent) -> List[ChainLinkEvent]:
        downstream = CHAIN_RULES.get(finding.payload.get('vuln_class'), [])
        events = []
        for d in downstream:
            hypothesis = {'vuln_class': d, 'is_testable': True}
            evt = ChainLinkEvent(scan_id=finding.scan_id, payload={'parent_finding_id': finding.payload.get('finding_id'), 'hypothesis': hypothesis, 'chain_depth': finding.payload.get('chain_depth', 1) + 1})
            events.append(evt)
            if self.producer:
                await self.producer.send_and_wait(evt.topic, json.dumps(evt.to_dict()).encode())
        return events
