-- Knowledge base for the Select phase (RAG over HackTricks + MITRE ATT&CK + PTES).
-- Run once against the Supabase Postgres instance (Database → Extensions must allow
-- `vector`). The ingestion scripts in scripts/kb/ populate this table; agent/knowledge.py
-- queries it via the match_knowledge RPC below.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS knowledge_corpus (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source               TEXT NOT NULL CHECK (source IN ('hacktricks', 'mitre', 'ptes')),
  title                TEXT,
  url                  TEXT,
  content              TEXT NOT NULL,
  ptes_phase           TEXT,          -- e.g. 'Exploitation', 'Vulnerability Analysis'
  attack_technique_id  TEXT,          -- e.g. 'T1190', 'T1550.001'
  tactic               TEXT,          -- MITRE tactic / kill-chain phase
  metadata             JSONB,
  embedding            vector(384),   -- all-MiniLM-L6-v2 dimensionality
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Approximate-nearest-neighbour index for cosine similarity. Build AFTER bulk ingest for
-- a better-balanced index; `lists` ~= sqrt(rows) is a reasonable default for tens of
-- thousands of rows.
CREATE INDEX IF NOT EXISTS idx_corpus_embedding
  ON knowledge_corpus USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE INDEX IF NOT EXISTS idx_corpus_filters
  ON knowledge_corpus (source, ptes_phase, attack_technique_id);


-- Similarity search RPC. Called from agent/knowledge.py via supabase.rpc('match_knowledge').
-- filter_source: text[] of sources to include (NULL = all). filter_phase: one PTES phase
-- (NULL = all). Returns the closest match_count rows with a cosine similarity score.
CREATE OR REPLACE FUNCTION match_knowledge(
  query_embedding vector(384),
  filter_source   text[]  DEFAULT NULL,
  filter_phase    text    DEFAULT NULL,
  match_count     int     DEFAULT 6
)
RETURNS TABLE (
  id                  uuid,
  source              text,
  title               text,
  url                 text,
  content             text,
  ptes_phase          text,
  attack_technique_id text,
  tactic              text,
  similarity          float
)
LANGUAGE sql STABLE
AS $$
  SELECT
    kc.id, kc.source, kc.title, kc.url, kc.content,
    kc.ptes_phase, kc.attack_technique_id, kc.tactic,
    1 - (kc.embedding <=> query_embedding) AS similarity
  FROM knowledge_corpus kc
  WHERE kc.embedding IS NOT NULL
    AND (filter_source IS NULL OR kc.source = ANY(filter_source))
    AND (filter_phase  IS NULL OR kc.ptes_phase = filter_phase)
  ORDER BY kc.embedding <=> query_embedding
  LIMIT match_count;
$$;
