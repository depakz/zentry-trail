-- Migration 001_initial.sql
-- Initial schema for scan-outcome-db

-- enable extension
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

SELECT create_hypertable('findings', 'created_at', if_not_exists => TRUE);
