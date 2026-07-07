"""Ingest MITRE ATT&CK Enterprise techniques into knowledge_corpus.

Downloads the official STIX 2.1 bundle (attack-stix-data on GitHub) and indexes each
attack-pattern (technique / sub-technique). Parsing the structured JSON directly avoids a
heavy stix2 dependency. Each row is tagged with source='mitre', the technique id
(e.g. T1190), the tactic, and a mapped PTES phase.

Usage:
    python scripts/kb/ingest_mitre.py
"""
import json
import urllib.request

from kb_common import TACTIC_TO_PTES, chunk_text, purge_source, upsert_chunks

STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
            "enterprise-attack/enterprise-attack.json")


def _technique_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def _tactic(obj: dict) -> str:
    phases = obj.get("kill_chain_phases", [])
    for p in phases:
        if p.get("kill_chain_name") == "mitre-attack":
            return p.get("phase_name", "")
    return ""


def main() -> None:
    print(f"[mitre] downloading STIX bundle …\n  {STIX_URL}")
    with urllib.request.urlopen(STIX_URL, timeout=120) as resp:
        bundle = json.loads(resp.read().decode("utf-8"))
    objects = bundle.get("objects", [])
    print(f"[mitre] {len(objects)} STIX objects")

    rows = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _technique_id(obj)
        if not tid:
            continue
        name = obj.get("name", "")
        desc = obj.get("description", "")
        tactic = _tactic(obj)
        ptes = TACTIC_TO_PTES.get(tactic, "Vulnerability Analysis")
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                url = ref.get("url", "")
                break
        # Prefix each chunk with the technique header so retrieval carries the id/name.
        for chunk in chunk_text(f"{tid} {name}. {desc}"):
            rows.append({
                "source": "mitre",
                "title": f"{tid} {name}",
                "url": url,
                "content": chunk,
                "ptes_phase": ptes,
                "attack_technique_id": tid,
                "tactic": tactic,
                "metadata": {"name": name},
            })

    print(f"[mitre] prepared {len(rows)} chunks from techniques")
    purge_source("mitre")
    written = upsert_chunks(rows)
    print(f"[mitre] done — {written} rows indexed")


if __name__ == "__main__":
    main()
