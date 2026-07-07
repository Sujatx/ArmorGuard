"""Shared helpers for the knowledge-base ingestion scripts.

Puts server/ on sys.path so the scripts reuse the exact same embedding model as the agent
(agent.knowledge.embed_texts) and the same Supabase client (database.get_db). This keeps
index-time and query-time embeddings identical — a hard requirement for vector search.

Run these from the repo root with the server virtualenv active:
    python scripts/kb/ingest_mitre.py
    python scripts/kb/ingest_ptes.py
    python scripts/kb/ingest_hacktricks.py --path /path/to/hacktricks
"""
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

# server/ holds both `database.py` and the `agent` package.
_SERVER = Path(__file__).resolve().parents[2] / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from agent.knowledge import embed_texts  # noqa: E402
from database import get_db               # noqa: E402

BATCH = 64  # rows embedded + upserted per round-trip


# MITRE tactic (kill-chain phase) → PTES phase, so all three sources share one phase axis.
TACTIC_TO_PTES = {
    "reconnaissance": "Intelligence Gathering",
    "resource-development": "Pre-engagement",
    "initial-access": "Exploitation",
    "execution": "Exploitation",
    "persistence": "Post-Exploitation",
    "privilege-escalation": "Post-Exploitation",
    "defense-evasion": "Exploitation",
    "credential-access": "Exploitation",
    "discovery": "Vulnerability Analysis",
    "lateral-movement": "Post-Exploitation",
    "collection": "Post-Exploitation",
    "command-and-control": "Post-Exploitation",
    "exfiltration": "Post-Exploitation",
    "impact": "Post-Exploitation",
}

# Coarse keyword → PTES phase mapping for unstructured sources (HackTricks / PTES text).
_PHASE_KEYWORDS = [
    ("Exploitation", ("exploit", "injection", "rce", "payload", "shell", "bypass", "forge")),
    ("Vulnerability Analysis", ("scan", "enumerat", "fingerprint", "discovery", "vulnerab")),
    ("Post-Exploitation", ("privilege", "persistence", "pivot", "exfiltrat", "lateral")),
    ("Intelligence Gathering", ("recon", "osint", "whois", "subdomain", "dns")),
    ("Reporting", ("report", "remediation", "evidence")),
]


def guess_phase(text: str) -> str:
    low = text.lower()
    for phase, keys in _PHASE_KEYWORDS:
        if any(k in low for k in keys):
            return phase
    return "Vulnerability Analysis"


def chunk_text(text: str, target: int = 600, overlap: int = 80) -> List[str]:
    """Split text into ~`target`-word chunks with a small overlap. Paragraph-aware so a
    chunk rarely cuts mid-sentence."""
    text = re.sub(r"\n{3,}", "\n\n", text or "").strip()
    if not text:
        return []
    words = text.split()
    if len(words) <= target:
        return [text]
    chunks, i = [], 0
    while i < len(words):
        chunk = " ".join(words[i:i + target])
        chunks.append(chunk)
        i += target - overlap
    return chunks


def upsert_chunks(rows: Iterable[Dict[str, Any]]) -> int:
    """Embed each row's `content` and insert into knowledge_corpus. Returns rows written.
    Skips embedding entirely (and aborts) if the model is unavailable, so a misconfigured
    environment fails loudly here rather than silently indexing NULL vectors."""
    rows = list(rows)
    if not rows:
        return 0
    db = get_db()
    written = 0
    for start in range(0, len(rows), BATCH):
        batch = rows[start:start + BATCH]
        vectors = embed_texts([r["content"] for r in batch])
        if not vectors:
            raise RuntimeError(
                "Embedding model unavailable — install sentence-transformers before ingesting."
            )
        for r, vec in zip(batch, vectors):
            r["embedding"] = vec
        db.table("knowledge_corpus").insert(batch).execute()
        written += len(batch)
        print(f"  ...upserted {written}/{len(rows)}", flush=True)
    return written


def purge_source(source: str) -> None:
    """Delete existing rows for a source so re-ingesting is idempotent."""
    try:
        get_db().table("knowledge_corpus").delete().eq("source", source).execute()
        print(f"[kb] cleared existing '{source}' rows")
    except Exception as e:
        print(f"[kb] purge_source({source}) skipped: {e}")
