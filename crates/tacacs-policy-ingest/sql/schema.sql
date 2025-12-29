-- SPDX-License-Identifier: AGPL-3.0-only
-- Create database objects for tacacs-policy-ingest

CREATE TABLE IF NOT EXISTS ingest_runs (
  id UUID PRIMARY KEY,
  repo_id TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  ref TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id UUID PRIMARY KEY,
  repo_id TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  location_code TEXT NOT NULL,
  policy_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (repo_id, commit_sha, location_code)
);

CREATE TABLE IF NOT EXISTS config_versions (
  id UUID PRIMARY KEY,
  repo_id TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  location_code TEXT NOT NULL,
  config_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (repo_id, commit_sha, location_code)
);

CREATE TABLE IF NOT EXISTS active_set (
  repo_id TEXT NOT NULL,
  location_code TEXT NOT NULL,
  active_commit_sha TEXT NOT NULL,
  activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_by TEXT NOT NULL,
  PRIMARY KEY (repo_id, location_code)
);
