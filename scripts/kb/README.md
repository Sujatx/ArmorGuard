# Knowledge base ingestion (Select-phase RAG)

Builds the `knowledge_corpus` pgvector table that the intent-driven pipeline's **Select**
phase queries. Three sources are combined on one schema (`source`, `ptes_phase`,
`attack_technique_id`) so retrieval can filter/join across all of them by phase and
technique:

| Source | What | How |
|---|---|---|
| **MITRE ATT&CK** | technique taxonomy (T1190, T1550.001, …) | STIX JSON download |
| **PTES** | engagement-phase methodology | MediaWiki scrape |
| **HackTricks** | operational payloads/procedures | local markdown clone |

All three embed with the **same** local model as the agent
(`sentence-transformers/all-MiniLM-L6-v2`, 384-dim, CPU-only) via
`server/agent/knowledge.py`, so index-time and query-time vectors match.

## One-time setup

1. Enable pgvector + create the table and RPC (Supabase SQL editor or psql):
   ```sql
   \i server/database/knowledge_schema.sql
   ```
2. Install the ingestion deps into the server virtualenv:
   ```bash
   pip install sentence-transformers beautifulsoup4
   ```
3. Ensure `SUPABASE_URL` / `SUPABASE_KEY` are set (same `.env` the backend uses).

## Run (from the repo root, server venv active)

```bash
python scripts/kb/embed.py "sql injection"          # sanity-check the embedder

python scripts/kb/ingest_mitre.py                    # ~1–2k technique chunks
python scripts/kb/ingest_ptes.py                     # a few hundred chunks

git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks /tmp/hacktricks
python scripts/kb/ingest_hacktricks.py --path /tmp/hacktricks   # add --limit N to sample
```

Each `ingest_*` is idempotent — it purges its own `source` rows before re-inserting. The
first run downloads the MiniLM model (~90 MB). Embedding runs on CPU; HackTricks is the
long pole (tens of minutes for the full corpus) — use `--limit` for a quick demo index.

## Verify

```sql
select source, count(*) from knowledge_corpus group by source;
```

If retrieval is disabled (model missing, `KNOWLEDGE_ENABLED=false`, or the table is
empty), the Select phase silently falls back to fingerprint-only tool selection — the
scan still runs, just without grounded citations.
