# Topic definitions for AVVP Kafka cluster
TOPICS = {
    "surface.seed": {"partitions": 3, "replication": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
    "recon.raw": {"partitions": 6, "replication": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
    "recon.normalized": {"partitions": 6, "replication": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
    "recon.deduped": {"partitions": 6, "replication": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
    "graph.updated": {"partitions": 3, "replication": 1, "retention_ms": 30 * 24 * 60 * 60 * 1000},
    "graph.ready": {"partitions": 3, "replication": 1, "retention_ms": 30 * 24 * 60 * 60 * 1000},
    "attack.plan": {"partitions": 6, "replication": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
    "validation.job": {"partitions": 12, "replication": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
    "validation.result": {"partitions": 12, "replication": 1, "retention_ms": 30 * 24 * 60 * 60 * 1000},
    "finding.confirmed": {"partitions": 6, "replication": 1, "retention_ms": 365 * 24 * 60 * 60 * 1000},
    "chain.link": {"partitions": 6, "replication": 1, "retention_ms": 30 * 24 * 60 * 60 * 1000},
    "evidence.sealed": {"partitions": 3, "replication": 1, "retention_ms": 365 * 24 * 60 * 60 * 1000},
    "gnn.train": {"partitions": 3, "replication": 1, "retention_ms": 30 * 24 * 60 * 60 * 1000},
    "metrics.events": {"partitions": 3, "replication": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
}
