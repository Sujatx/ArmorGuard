"""Select-phase knowledge base (RAG over HackTricks + MITRE ATT&CK + PTES).

Two jobs:
  1. ``embed_texts`` — turn text into 384-dim vectors with a local sentence-transformers
     model (CPU-only, no API key). Shared with the ingestion scripts in scripts/kb so the
     query-time and index-time embeddings come from the exact same model.
  2. ``retrieve`` — embed a query and pull the most relevant playbook chunks from the
     ``knowledge_corpus`` pgvector table via the ``match_knowledge`` Postgres RPC, filtered
     by source and PTES phase.

Everything degrades gracefully: if sentence-transformers isn't installed, KNOWLEDGE_ENABLED
is false, or the DB/RPC is unavailable, ``retrieve`` returns ``[]`` and the Select phase
falls back to fingerprint-only tool selection. The scan never fails for want of the KB.
"""
import logging
from typing import Any, Dict, List, Optional

from agent.config import EMBEDDING_MODEL, EMBEDDING_DIM, KNOWLEDGE_ENABLED

_log = logging.getLogger("armorguard.knowledge")

_embedder = None
_embedder_failed = False


def get_embedder():
    """Load and cache the sentence-transformers model once. Returns None if the library
    or model is unavailable (so callers degrade instead of crashing)."""
    global _embedder, _embedder_failed
    if _embedder is not None or _embedder_failed:
        return _embedder
    try:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer(EMBEDDING_MODEL, device="cpu")
        _log.info("Loaded embedding model %s", EMBEDDING_MODEL)
    except Exception as e:
        _embedder_failed = True
        _log.warning("Embedding model unavailable (%s) — retrieval disabled.", e)
    return _embedder


def embed_texts(texts: List[str]) -> List[List[float]]:
    """Embed a batch of texts to 384-dim vectors. Returns [] if the model is unavailable."""
    model = get_embedder()
    if model is None:
        return []
    vectors = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return [v.tolist() for v in vectors]


def embed_one(text: str) -> Optional[List[float]]:
    vecs = embed_texts([text])
    return vecs[0] if vecs else None


def retrieve(query: str, phase: Optional[str] = None,
             sources: Optional[List[str]] = None, k: int = 6) -> List[Dict[str, Any]]:
    """Return up to ``k`` playbook chunks most relevant to ``query``.

    Each chunk: {source, title, url, content, ptes_phase, attack_technique_id, similarity}.
    Filters: ``phase`` restricts to one PTES phase; ``sources`` restricts to a subset of
    {'hacktricks','mitre','ptes'}. Returns [] on any failure — never raises to the caller.
    """
    if not KNOWLEDGE_ENABLED:
        return []
    vector = embed_one(query)
    if vector is None:
        return []
    try:
        from database import get_db
        params = {
            "query_embedding": vector,
            "filter_source": sources,          # NULL/None → no source filter in the RPC
            "filter_phase": phase,
            "match_count": k,
        }
        res = get_db().rpc("match_knowledge", params).execute()
        return res.data or []
    except Exception as e:
        _log.warning("match_knowledge RPC failed (%s) — retrieval skipped.", e)
        return []


def format_playbook(chunks: List[Dict[str, Any]], max_chars: int = 2400) -> str:
    """Render retrieved chunks into a compact context block for the Select LLM prompt."""
    if not chunks:
        return "(no playbook context retrieved)"
    lines: List[str] = []
    used = 0
    for c in chunks:
        tag = c.get("attack_technique_id") or c.get("source", "kb")
        phase = c.get("ptes_phase") or ""
        snippet = (c.get("content") or "").strip().replace("\n", " ")
        entry = f"- [{tag}{'/' + phase if phase else ''}] {c.get('title', '')}: {snippet}"
        entry = entry[:600]
        if used + len(entry) > max_chars:
            break
        lines.append(entry)
        used += len(entry)
    return "\n".join(lines)
