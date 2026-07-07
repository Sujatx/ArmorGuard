-- Migration 002 — intent-driven ("autonomous") pipeline.
-- Idempotent ALTERs to bring an existing ArmorGuard database (created from schema.sql v1)
-- up to date. Safe to run more than once. For a fresh install, schema.sql already includes
-- all of this; run knowledge_schema.sql separately for the RAG table.

-- 1. Allow the new scan mode. CHECK constraints can't be altered in place, so drop + re-add.
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_scan_mode_check;
ALTER TABLE scans ADD CONSTRAINT scans_scan_mode_check
  CHECK (scan_mode IN ('default', 'deep', 'custom', 'autonomous'));

-- 2. Columns the pipeline persists.
ALTER TABLE scans    ADD COLUMN IF NOT EXISTS summary       TEXT;
ALTER TABLE scans    ADD COLUMN IF NOT EXISTS fingerprints  JSONB;
-- Terminal wall-clock time, powering the live scan-duration timer in the UI.
ALTER TABLE scans    ADD COLUMN IF NOT EXISTS completed_at  TIMESTAMPTZ;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS confirmed            BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS proof                TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_technique_id  TEXT;
