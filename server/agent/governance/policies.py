from typing import List

# Order matters — the pipeline runs strictly left to right:
#   discovery (katana crawl, ffuf route brute) → parameter discovery (arjun) →
#   probe/attack (httpx, nuclei, nikto, sqlmap).
# Attack tools read the endpoints/parameters discovery wrote into the scan context,
# so discovery MUST precede them. arjun must precede sqlmap (it supplies the params).
TOOLS_BY_MODE = {
    "default": ["nmap", "katana", "ffuf", "httpx", "nuclei"],
    "deep":    ["nmap", "katana", "ffuf", "arjun", "httpx", "nuclei", "nikto", "sqlmap", "hydra"],
    # The intent-driven pipeline declares the *superset* it may reach for. Which of these
    # actually run is decided at runtime by the Select phase (LLM + fingerprint gates),
    # not here — but every one must be on the ArmorIQ allow-list up front so an eligible
    # tool is never blocked server-side as off-policy.
    "autonomous": [
        "nmap", "katana", "ffuf", "arjun", "httpx", "nuclei", "nikto",
        "sqlmap", "hydra", "jwt_tool", "graphql_cop", "commix", "odat",
    ],
}
# The full roster of governed tool names (union across every mode).
VALID_TOOLS = set(TOOLS_BY_MODE["deep"]) | set(TOOLS_BY_MODE["autonomous"])

# Exploitation-tier tools may only run once a fingerprint signal confirms the surface.
# Enforcement of the gate lives in agent.SCANNERS[...].is_eligible; this set is the
# authoritative list of names that are gated, used by Select to partition the roster.
EXPLOIT_TIER_TOOLS = {"sqlmap", "hydra", "jwt_tool", "graphql_cop", "commix", "odat"}


def get_tools_for_mode(scan_mode: str, selected_tools: List[str]) -> List[str]:
    if scan_mode == "custom":
        return [t for t in selected_tools if t in VALID_TOOLS]
    return TOOLS_BY_MODE.get(scan_mode, TOOLS_BY_MODE["default"])


# The report/summary phase isn't a scanner — it's a distinct governed action so the
# delegated report token (and its bound session) can authorise the LLM summary, which is
# the documented prompt-injection drift point.
REPORT_ACTION = "summarize"


def build_armoriq_plan(tools: List[str], target_url: str, scan_mode: str) -> dict:
    # Append the report step so the root plan declares every governed action — including
    # the summary the report sub-agent runs under its delegated token.
    return {"steps": [{"action": t} for t in tools] + [{"action": REPORT_ACTION}]}


def build_armoriq_policy(tools: List[str], target_url: str) -> dict:
    """Client-side policy hint passed to ``get_intent_token(policy=...)`` so the
    minted token carries the scanner allow-list and approved-target scope. The
    authoritative enforcement still happens server-side (policy_snapshot on the
    token + ``/iap/sdk/enforce``); this just declares the agent's intended scope
    so the dashboard can validate it. ``defaultEnforcementAction`` mirrors the
    dashboard policy so anything off-list is blocked rather than held."""
    scope = target_url.rstrip("/")
    return {
        "allowedTools": list(tools),
        "targetScope": {
            "allowedTargets": [scope],
            "defaultEnforcementAction": "block",
        },
        "defaultEnforcementAction": "block",
    }


# Phase → tool grouping for the orchestrator + governed sub-agents (Workstream D).
# Each sub-agent receives a delegated token scoped to exactly its phase's tools.
#   recon   maps the attack surface (writes discovered_urls / discovered_params)
#   exploit attacks that surface (reads recon output)
#   report  summarises (where the prompt-injection drift fires)
PHASE_TOOLS = {
    "recon":   ["nmap", "katana", "ffuf", "arjun"],
    "exploit": ["httpx", "nuclei", "nikto", "sqlmap", "hydra"],
}


def group_tools_by_phase(tools: List[str]) -> dict:
    """Partition a tool list into ordered (phase, [tools]) preserving the
    pipeline order within each phase. Tools not in any phase are ignored."""
    grouped = {}
    for phase, phase_tools in PHASE_TOOLS.items():
        selected = [t for t in tools if t in phase_tools]
        if selected:
            grouped[phase] = selected
    return grouped


# Intent-driven pipeline phases. Fingerprint runs the lightweight probes; attack/confirm
# run the eligible offensive tools. Each sub-agent gets a delegated token scoped to its
# phase's tools, exactly like the deterministic recon/exploit split above.
AUTONOMOUS_PHASE_TOOLS = {
    "fingerprint": ["nmap", "httpx", "katana", "arjun"],
    "attack":      ["nuclei", "nikto", "sqlmap", "hydra",
                    "jwt_tool", "graphql_cop", "commix", "odat"],
}


def group_tools_autonomous(tools: List[str]) -> dict:
    """Partition the autonomous roster into fingerprint/attack phases for token delegation.
    Confirm reuses the attack phase's scope (it runs the same offensive tools to prove a
    finding), so it needs no separate grouping."""
    grouped = {}
    for phase, phase_tools in AUTONOMOUS_PHASE_TOOLS.items():
        selected = [t for t in tools if t in phase_tools]
        if selected:
            grouped[phase] = selected
    return grouped
