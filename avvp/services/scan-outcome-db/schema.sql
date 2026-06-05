-- avvp/services/scan-outcome-db/schema.sql

-- Tables required:
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

CREATE TABLE IF NOT EXISTS scans (
  scan_id UUID PRIMARY KEY,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  config JSONB
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id UUID PRIMARY KEY,
  scan_id UUID REFERENCES scans(scan_id),
  vuln_class TEXT NOT NULL,
  severity TEXT NOT NULL,
  chain_depth INTEGER DEFAULT 1,
  confirmed BOOLEAN DEFAULT FALSE,
  evidence_bundle_id TEXT,
  sarif JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attack_graph_snapshots (
  snapshot_id UUID PRIMARY KEY,
  scan_id UUID,
  graph_json JSONB,
  node_count INTEGER,
  edge_count INTEGER,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TimescaleDB hypertable for findings.created_at
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'findings') THEN
    -- findings table created above
    NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'findings') THEN
    NULL;
  END IF;
EXCEPTION WHEN OTHERS THEN
  NULL;
END$$;

-- Create hypertable if not exists
SELECT create_hypertable('findings', 'created_at', if_not_exists => TRUE);
