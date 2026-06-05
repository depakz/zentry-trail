#!/usr/bin/env python3
"""Create Kafka topics defined in avvp/infra/kafka/topics.py
Usage: python kafka_topics.py --create-all --bootstrap localhost:9092
"""
import argparse
from kafka.admin import KafkaAdminClient, NewTopic
from avvp.infra.kafka.topics import TOPICS


def create_all(bootstrap_servers: str = "localhost:9092"):
    admin = KafkaAdminClient(bootstrap_servers=bootstrap_servers, client_id="avvp-topic-creator")
    topics = []
    for name, cfg in TOPICS.items():
        partitions = int(cfg.get("partitions", 1))
        replication = int(cfg.get("replication", 1))
        topics.append(NewTopic(name=name, num_partitions=partitions, replication_factor=replication))
    try:
        existing = admin.list_topics()
        to_create = [t for t in topics if t.name not in existing]
        if not to_create:
            print("No new topics to create; all exist")
            return
        admin.create_topics(new_topics=to_create, validate_only=False)
        print(f"Created {len(to_create)} topics")
    except Exception as e:
        print("Error creating topics:", e)
    finally:
        admin.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-all", action="store_true", help="Create all topics")
    parser.add_argument("--bootstrap", default="localhost:9092", help="Kafka bootstrap servers")
    args = parser.parse_args()

    if args.create_all:
        create_all(bootstrap_servers=args.bootstrap)
    else:
        parser.print_help()
