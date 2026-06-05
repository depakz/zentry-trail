from neo4j import GraphDatabase
from typing import Dict, Any

class AttackGraphService:
    def __init__(self, uri: str = "bolt://127.0.0.1:7687", user: str = "neo4j", password: str = "test"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def add_endpoint(self, scan_id: str, endpoint: Dict[str, Any]):
        # endpoint: {"url":..., "method":..., "status_code":..., "params": [...]}
        session = self.driver.session()
        # use explicit session API to accommodate test fakes
        session.write_transaction(self._create_endpoint_tx, scan_id, endpoint)

    @staticmethod
    def _create_endpoint_tx(tx, scan_id: str, endpoint: Dict[str, Any]):
        url = endpoint.get("url")
        method = endpoint.get("method", "GET")
        status = endpoint.get("status_code")
        params = endpoint.get("params", [])
        tx.run(
            "MERGE (t:Target {scan_id:$scan_id}) "
            "MERGE (e:Endpoint {url:$url}) "
            "ON CREATE SET e.method=$method, e.status_code=$status "
            "MERGE (t)-[:HAS_ENDPOINT]->(e)",
            scan_id=scan_id, url=url, method=method, status=status
        )
        for p in params:
            tx.run(
                "MERGE (param:Parameter {name:$p})"
                "MERGE (e:Endpoint {url:$url})"
                "MERGE (e)-[:HAS_PARAM]->(param)",
                p=p, url=url
            )
