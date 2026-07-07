"""Thin CLI wrapper around the shared embedding model.

The real embedding logic lives in server/agent/knowledge.py so query-time (agent) and
index-time (these scripts) embeddings come from the identical model. This module just
re-exports it and offers a quick sanity check:

    python scripts/kb/embed.py "test sql injection"   # prints the vector dimensionality
"""
import sys
from pathlib import Path

_SERVER = Path(__file__).resolve().parents[2] / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from agent.knowledge import embed_texts, embed_one  # noqa: E402,F401


if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else "exploit public-facing application"
    vec = embed_one(text)
    if vec is None:
        print("Embedding model unavailable — install sentence-transformers.")
        sys.exit(1)
    print(f"Embedded {text!r} → {len(vec)}-dim vector (first 5: {[round(x, 4) for x in vec[:5]]})")
