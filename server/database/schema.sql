CREATE TABLE consent_records (

  consent_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  target_url     TEXT NOT NULL,

  operator_ip    TEXT NOT NULL,

  timestamp      TIMESTAMPTZ NOT NULL DEFAULT now(),

  acknowledged   BOOLEAN NOT NULL DEFAULT false

);

CREATE TABLE scans (

  scan_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  target_url     TEXT NOT NULL,

  scan_mode      TEXT NOT NULL CHECK (scan_mode IN ('default', 'deep', 'custom', 'autonomous')),

  selected_tools TEXT[],

  status         TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')) DEFAULT 'running',

  progress       INTEGER NOT NULL DEFAULT 0,

  summary        TEXT,

  fingerprints   JSONB,

  consent_id     UUID REFERENCES consent_records(consent_id),

  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  completed_at   TIMESTAMPTZ

);

CREATE TABLE findings (

  finding_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  scan_id        UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,

  severity       TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),

  title          TEXT NOT NULL,

  description    TEXT NOT NULL,

  remediation    TEXT NOT NULL,

  evidence       TEXT,

  -- Intent-driven pipeline: proven-only reporting. `confirmed` is TRUE once the Confirm
  -- phase demonstrated the vuln with an active PoC; `proof` holds the evidence of access
  -- (extracted data / command output / replayed-token response); `attack_technique_id`
  -- is the MITRE ATT&CK id of the technique. Deterministic-mode findings leave these NULL.
  confirmed            BOOLEAN NOT NULL DEFAULT false,

  proof                TEXT,

  attack_technique_id  TEXT,

  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()

);

CREATE TABLE audit_log_events (

  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  scan_id        UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,

  event_type     TEXT NOT NULL,

  message        TEXT NOT NULL,

  metadata       JSONB,

  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()

);

CREATE TABLE intent_drift_events (

  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  scan_id              UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,

  error_code           TEXT NOT NULL,

  block_reason         TEXT NOT NULL,

  drift_classification TEXT NOT NULL CHECK (drift_classification IN ('prompt_injection', 'hallucination')),

  attempted_action     TEXT NOT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()

);

-- Indexes for the lookups the API actually does

CREATE INDEX idx_findings_scan_id ON findings(scan_id);

CREATE INDEX idx_audit_log_scan_id ON audit_log_events(scan_id);

CREATE INDEX idx_drift_events_scan_id ON intent_drift_events(scan_id);

CREATE INDEX idx_scans_created_at ON scans(created_at DESC); -- for GET /sessions ordering
