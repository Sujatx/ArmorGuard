"""Ingest the PTES methodology (pentest-standard.org) into knowledge_corpus.

PTES has no structured export, so we scrape the MediaWiki phase pages and chunk their
content. Each page maps to one PTES phase, which becomes the shared `ptes_phase` axis.

Usage:
    python scripts/kb/ingest_ptes.py
"""
import urllib.request

from kb_common import chunk_text, purge_source, upsert_chunks

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    raise SystemExit("beautifulsoup4 is required: pip install beautifulsoup4")

BASE = "http://www.pentest-standard.org/index.php/"

# MediaWiki page → PTES phase label.
PAGES = {
    "Pre-engagement": "Pre-engagement",
    "Intelligence_Gathering": "Intelligence Gathering",
    "Threat_Modeling": "Threat Modeling",
    "Vulnerability_Analysis": "Vulnerability Analysis",
    "Exploitation": "Exploitation",
    "Post_Exploitation": "Post-Exploitation",
    "Reporting": "Reporting",
    "PTES_Technical_Guidelines": "Vulnerability Analysis",
}


def _fetch(page: str) -> str:
    url = BASE + page
    req = urllib.request.Request(url, headers={"User-Agent": "ArmorGuard-KB/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        html = resp.read().decode("utf-8", "replace")
    soup = BeautifulSoup(html, "html.parser")
    content = soup.find("div", {"id": "mw-content-text"})
    if content is None:
        return ""
    # Drop edit links / tables of contents; keep readable prose.
    for tag in content.select(".mw-editsection, #toc, script, style"):
        tag.decompose()
    return content.get_text("\n", strip=True)


def main() -> None:
    rows = []
    for page, phase in PAGES.items():
        print(f"[ptes] fetching {page} …")
        try:
            text = _fetch(page)
        except Exception as e:
            print(f"[ptes]   skip {page}: {e}")
            continue
        url = BASE + page
        for chunk in chunk_text(text):
            rows.append({
                "source": "ptes",
                "title": page.replace("_", " "),
                "url": url,
                "content": chunk,
                "ptes_phase": phase,
                "attack_technique_id": None,
                "tactic": None,
                "metadata": {"page": page},
            })
    print(f"[ptes] prepared {len(rows)} chunks")
    purge_source("ptes")
    written = upsert_chunks(rows)
    print(f"[ptes] done — {written} rows indexed")


if __name__ == "__main__":
    main()
