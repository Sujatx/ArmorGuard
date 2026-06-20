from typing import List

# Order matters — the pipeline runs strictly left to right:
#   discovery (katana crawl, ffuf route brute) → parameter discovery (arjun) →
#   probe/attack (httpx, nuclei, nikto, sqlmap).
# Attack tools read the endpoints/parameters discovery wrote into the scan context,
# so discovery MUST precede them. arjun must precede sqlmap (it supplies the params).
TOOLS_BY_MODE = {
    "default": ["nmap", "katana", "ffuf", "httpx", "nuclei"],
    "deep":    ["nmap", "katana", "ffuf", "arjun", "httpx", "nuclei", "nikto", "sqlmap", "hydra"],
}
VALID_TOOLS = set(TOOLS_BY_MODE["deep"])


def get_tools_for_mode(scan_mode: str, selected_tools: List[str]) -> List[str]:
    if scan_mode == "custom":
        return [t for t in selected_tools if t in VALID_TOOLS]
    return TOOLS_BY_MODE.get(scan_mode, TOOLS_BY_MODE["default"])


def build_armoriq_plan(tools: List[str], target_url: str, scan_mode: str) -> dict:
    return {"steps": [{"action": t} for t in tools]}
