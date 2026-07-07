"""Ingest the HackTricks corpus into knowledge_corpus.

HackTricks is a large markdown book. Point this at a local clone (recommended — the repo
is big) and it walks every .md file, chunks by content, tags source='hacktricks', and
best-effort maps each chunk to a PTES phase by keyword.

    git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks /tmp/hacktricks
    python scripts/kb/ingest_hacktricks.py --path /tmp/hacktricks [--limit 2000]
"""
import argparse
import re
from pathlib import Path

from kb_common import chunk_text, guess_phase, purge_source, upsert_chunks

# Common web/exploitation technique names → MITRE id, so HackTricks chunks join the same
# technique axis as MITRE where an obvious mapping exists.
_TECHNIQUE_HINTS = {
    "sql injection": "T1190",
    "command injection": "T1059",
    "deserialization": "T1190",
    "jwt": "T1550.001",
    "saml": "T1606.002",
    "graphql": "T1190",
    "ssrf": "T1190",
    "xxe": "T1190",
    "file inclusion": "T1190",
    "path traversal": "T1190",
    "brute force": "T1110",
}


def _title_for(path: Path, text: str) -> str:
    m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return path.stem.replace("-", " ").title()


def _technique_for(text: str) -> str:
    low = text.lower()
    for name, tid in _TECHNIQUE_HINTS.items():
        if name in low:
            return tid
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True, help="Path to a local hacktricks clone")
    ap.add_argument("--limit", type=int, default=0, help="Max markdown files (0 = all)")
    args = ap.parse_args()

    root = Path(args.path)
    if not root.exists():
        raise SystemExit(f"path not found: {root}")

    md_files = sorted(root.rglob("*.md"))
    if args.limit:
        md_files = md_files[:args.limit]
    print(f"[hacktricks] {len(md_files)} markdown file(s)")

    rows = []
    for i, path in enumerate(md_files, 1):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # Skip nav/stub pages.
        if len(text) < 200:
            continue
        title = _title_for(path, text)
        rel = str(path.relative_to(root))
        for chunk in chunk_text(text):
            rows.append({
                "source": "hacktricks",
                "title": title,
                "url": f"hacktricks/{rel}",
                "content": chunk,
                "ptes_phase": guess_phase(chunk),
                "attack_technique_id": _technique_for(chunk),
                "tactic": None,
                "metadata": {"file": rel},
            })
        if i % 200 == 0:
            print(f"  scanned {i}/{len(md_files)} files, {len(rows)} chunks so far")

    print(f"[hacktricks] prepared {len(rows)} chunks")
    purge_source("hacktricks")
    written = upsert_chunks(rows)
    print(f"[hacktricks] done — {written} rows indexed")


if __name__ == "__main__":
    main()
