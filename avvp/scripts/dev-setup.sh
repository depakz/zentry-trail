#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="$(dirname "$0")/../docker-compose.dev.yml"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Bringing up development stack..."
DockerCompose="docker compose -f $COMPOSE_FILE"
$DockerCompose up -d

# wait helpers
wait_for() {
  name=$1
  shift
  echo -n "Waiting for $name"
  for i in {1..60}; do
    if "$@" >/dev/null 2>&1; then
      echo " OK"
      return 0
    fi
    echo -n '.'
    sleep 2
  done
  echo "\nTimed out waiting for $name" >&2
  return 1
}

wait_for "redis" redis-cli -h 127.0.0.1 ping
wait_for "postgres" pg_isready -h 127.0.0.1 -p 5432 -U avvp
wait_for "kafka" bash -c "</dev/tcp/127.0.0.1/9092 >/dev/null 2>&1"
wait_for "vault" bash -c "curl -sSf http://127.0.0.1:8200/v1/sys/health >/dev/null"
wait_for "neo4j" bash -c "curl -sSf http://127.0.0.1:7474/ >/dev/null"
wait_for "minio" bash -c "curl -sSf http://127.0.0.1:9000/minio/health/live >/dev/null"

# Create Kafka topics (requires scripts/kafka_topics.py)
if [ -x "$REPO_ROOT/avvp/scripts/kafka_topics.py" ] || [ -f "$REPO_ROOT/avvp/scripts/kafka_topics.py" ]; then
  echo "Creating Kafka topics..."
  python3 "$REPO_ROOT/avvp/scripts/kafka_topics.py" --create-all || echo "kafka_topics script failed"
else
  echo "Warning: kafka_topics.py not found; skip topic creation"
fi

# Run DB migrations if present
if [ -d "$REPO_ROOT/avvp/services/scan-outcome-db/migrations" ]; then
  echo "Running DB migrations..."
  # Placeholder: implement migrations runner
fi

# Seed Vault dev secrets
echo "Seeding Vault dev secrets (token=root)..."
if command -v vault >/dev/null 2>&1; then
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN=root
  vault kv put secret/osint/api_keys shodan="" censys=""
  vault kv put secret/evidence/signing_key private_key="" public_key=""
else
  echo "vault CLI not available - skipping seeding"
fi

echo "Development stack is up."
