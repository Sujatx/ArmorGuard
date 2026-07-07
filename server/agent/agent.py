import asyncio
import re
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, List, Optional, TypedDict

from langgraph.graph import StateGraph, START, END
from langchain_core.messages import SystemMessage, HumanMessage
from armoriq_sdk import PolicyBlockedException, IntentMismatchException

from agent.config import LLM_PROVIDER
from agent.llm import get_model, NmapFindings
from agent.models import AttackPlan
from agent.governance.armoriq_client import client as armoriq_client, governance
from agent.governance.policies import (
    get_tools_for_mode, build_armoriq_plan, build_armoriq_policy,
    group_tools_by_phase, group_tools_autonomous, EXPLOIT_TIER_TOOLS, REPORT_ACTION,
)
from agent import fingerprint as fp_mod
from agent import knowledge as kb
from agent.confirm import confirm_finding
from agent.tools.nmap_tool import run_nmap_scan, classify_ports_deterministic, skip_standard_web_ports
from agent.tools.katana_tool import run_katana_crawl
from agent.tools.ffuf_tool import run_ffuf_scan
from agent.tools.arjun_tool import run_arjun_scan
from agent.tools.nuclei_tool import run_nuclei_scan
from agent.tools.nikto_tool import run_nikto_scan
from agent.tools.httpx_tool import run_httpx_scan
from agent.tools.sqlmap_tool import run_sqlmap_scan
from agent.tools.hydra_tool import run_hydra_scan
from agent.tools.jwt_tool import run_jwt_scan
from agent.tools.graphql_cop_tool import run_graphql_cop_scan
from agent.tools.commix_tool import run_commix_scan
from agent.tools.odat_tool import run_odat_scan


# --- Working buffer the scanners read/write -----------------------------------------
# The durable scan data lives in the LangGraph ScanState (a dict); each node builds a
# ScanContext from it so the existing scanner adapters keep their simple object API
# (ctx.discovered_urls etc.) and the node writes the mutated discovery surface back into
# the graph state afterwards.
@dataclass
class ScanContext:
    scan_id: str
    target_url: str
    scan_mode: str
    selected_tools: List[str]
    broadcast: Any
    discovered_urls: List[str] = field(default_factory=list)
    discovered_params: List[str] = field(default_factory=list)
    # Intent-driven pipeline only: signals from Fingerprint, consumed by Select's
    # eligibility gates and by the attack/confirm tools. A plain dict (not the Pydantic
    # Fingerprint) so scanner adapters can read it with .get() like the rest of the ctx.
    fingerprints: dict = field(default_factory=dict)


# --- LangGraph state ----------------------------------------------------------------
class ScanState(TypedDict, total=False):
    scan_id: str
    target_url: str
    scan_mode: str
    selected_tools: List[str]
    tools: List[str]
    phases: dict
    root_token: Any
    recon_token: Any
    exploit_token: Any
    report_token: Any
    discovered_urls: List[str]
    discovered_params: List[str]
    results: dict
    halted: bool
    # Intent-driven ("autonomous") pipeline additions.
    fingerprints: dict          # structured signals from the Fingerprint phase
    attack_plan: List[dict]     # ordered [{tool, rationale, techniqueId}] from Select
    findings: List[dict]        # unconfirmed findings collected in Attack, verified in Confirm


async def _emit_drift(broadcast, exc: Exception, attempted_action: str) -> None:
    """Record an ArmorIQ policy block as an intent-drift incident (no halt)."""
    meta = getattr(exc, "metadata", {}) or {}
    drift_class = meta.get("drift_classification", "prompt_injection")
    error_code = getattr(exc, "reason", "blocked")

    # Only coerce out_of_scope_target to hallucination if it's NOT already explicitly
    # tagged as prompt_injection (the demo prompt injection uses an out-of-scope target,
    # so we must preserve its classification).
    if error_code == "out_of_scope_target" and drift_class != "prompt_injection":
        drift_class = "hallucination"

    matched_policy = meta.get("matched_policy") or meta.get("matchedPolicy")
    await broadcast({"event": "intent_drift_detected", "data": {
        "errorCode": error_code,
        "blockReason": str(exc),
        "driftClassification": drift_class,
        "attemptedAction": attempted_action,
        "matchedPolicy": matched_policy,
    }})


async def _handle_armoriq_block(broadcast, exc: Exception, attempted_action: str) -> None:
    """Record the incident AND halt the scan. Used by the recon/exploit sub-agents, where a
    block means the agent is being redirected mid-scan and active scanning must stop."""
    await _emit_drift(broadcast, exc, attempted_action)
    error_code = getattr(exc, "reason", "blocked")
    await broadcast({"event": "agent_halted", "data": {
        "reason": f"ArmorIQ blocked {attempted_action}: {error_code}",
    }})


async def _armoriq_gate(approved_target: str, action: str, target: str,
                        params: Optional[dict], token: Any) -> None:
    """Gate a tool/action through ArmorIQ before it runs, scoped to the caller's token.

    Three layers, in order:
      1. token validity (expiry) — a benign timeout, not drift.
      2. deterministic scope backstop — blocks any off-scope target locally so the
         prompt-injection demo halts even when no dashboard policy is configured.
      3. real ArmorIQ enforcement (``governance.enforce`` → ``/iap/sdk/enforce``) —
         server-side allow/block/hold against the policy on the (delegated) token.

    Each sub-agent passes its own delegated token, so enforcement is scoped to exactly
    the phase that sub-agent is allowed to run."""
    params = params if params is not None else {"target": target}

    # Check expiry directly — the SDK's verify_token also validates signature/plan_hash
    # which can be absent on delegation responses (the SDK defaults expires_at=0 when the
    # field is missing), causing a false "expired" block. Layer 1 is only about timeout.
    valid = token is not None and (time.time() < getattr(token, "expires_at", 0))
    if not valid:
        raise IntentMismatchException(
            f"Intent token expired before {action}",
            action=action,
        )

    # Deterministic local backstop — independent of any dashboard policy.
    approved = approved_target.rstrip("/")
    if target.rstrip("/") != approved:
        raise PolicyBlockedException(
            f"Target '{target}' is outside the approved scan scope '{approved}'",
            reason="out_of_scope_target",
            metadata={"drift_classification": "prompt_injection"},
        )

    # Real server-side enforcement (no-op allow in mock mode / when policy absent).
    decision = await asyncio.to_thread(
        governance.enforce, token, action, target, params,
    )
    if not decision.allowed or decision.action in ("block", "hold"):
        reason = decision.reason or decision.action
        raise PolicyBlockedException(
            decision.reason or f"ArmorIQ {decision.action} on {action}",
            reason=reason,
            metadata={
                "drift_classification": _classify_drift(reason),
                "matched_policy": decision.matched_policy,
            },
        )


def _classify_drift(reason: str) -> str:
    """Classify why ArmorIQ blocked an action so the incident is labelled honestly,
    within the two-value taxonomy the DB allows ('prompt_injection' | 'hallucination').
    Only genuine injection signals get ``prompt_injection``; an off-scope target or an
    allow-list / policy-constraint miss is the agent deviating from what it may do, which
    this codebase records as ``hallucination`` (see the out_of_scope_target path)."""
    r = (reason or "").lower()
    if any(x in r for x in ("injection", "exfiltrate", "malicious", "jailbreak")):
        return "prompt_injection"
    return "hallucination"


# --- Scanner registry -------------------------------------------------------------
# Each scanner declares how to run and how to describe itself; the generic runner
# (`_run_scanner`) handles the identical lifecycle every tool used to copy-paste:
# broadcast "running" → ArmorIQ gate → execute in a thread → stream findings →
# broadcast "done". nmap is the one exception (its findings come from an async LLM
# interpretation step) and is handled by `_run_nmap`.

@dataclass
class Scanner:
    name: str
    description: str
    run: Callable[[ScanContext], List[dict]]   # sync; executed via asyncio.to_thread
    running_message: str = ""
    done_message: Optional[Callable[[ScanContext, List[dict]], str]] = None
    # Intent-driven metadata. `category` groups tools by attack surface; `tier` marks a
    # tool as recon (always eligible) or exploit (must pass `eligible`); `technique_id`
    # is the MITRE ATT&CK id surfaced in Select reasoning and the report. `eligible`
    # reads ctx.fingerprints and decides whether the tool is warranted for THIS target —
    # generalising hydra's inline `_has_http_basic_auth` guard into the registry.
    category: str = "recon"
    tier: str = "recon"
    technique_id: str = ""
    eligible: Optional[Callable[[ScanContext], bool]] = None

    def is_eligible(self, ctx: ScanContext) -> bool:
        """Recon tools are always eligible; exploit tools defer to their predicate
        (default: not eligible without an explicit fingerprint signal)."""
        if self.eligible is not None:
            try:
                return bool(self.eligible(ctx))
            except Exception:
                return False
        return self.tier == "recon"


def _katana_run(deps: ScanContext) -> List[dict]:
    urls, params = run_katana_crawl(deps.target_url, deps.scan_id)
    deps.discovered_urls = urls
    deps.discovered_params = params
    return []  # discovery maps the surface; it does not itself report vulnerabilities


def _httpx_run(deps: ScanContext) -> List[dict]:
    return run_httpx_scan(deps.target_url, deps.scan_id)


def _nuclei_run(deps: ScanContext) -> List[dict]:
    targets = deps.discovered_urls or [deps.target_url]
    return run_nuclei_scan(targets, deps.scan_id, aggressive=(deps.scan_mode == "deep"))


def _ffuf_run(deps: ScanContext) -> List[dict]:
    routes = run_ffuf_scan(deps.target_url, deps.scan_id)
    deps.discovered_urls = sorted(dict.fromkeys((deps.discovered_urls or []) + routes))
    return []


def _arjun_run(deps: ScanContext) -> List[dict]:
    param_urls = run_arjun_scan(deps.discovered_urls or [deps.target_url], deps.scan_id)
    deps.discovered_params = sorted(dict.fromkeys((deps.discovered_params or []) + param_urls))
    return []


def _nikto_run(deps: ScanContext) -> List[dict]:
    return run_nikto_scan(deps.target_url, deps.scan_id)


def _sqlmap_run(deps: ScanContext) -> List[dict]:
    return run_sqlmap_scan(deps.target_url, deps.scan_id, param_urls=deps.discovered_params or None)


def _hydra_run(deps: ScanContext) -> List[dict]:
    return run_hydra_scan(deps.target_url, deps.scan_id)


# --- Intent-driven tool adapters --------------------------------------------------

def _jwt_run(deps: ScanContext) -> List[dict]:
    return run_jwt_scan(deps.target_url, deps.scan_id, fingerprints=deps.fingerprints)


def _graphql_cop_run(deps: ScanContext) -> List[dict]:
    endpoints = (deps.fingerprints or {}).get("graphql_endpoints") or []
    return run_graphql_cop_scan(deps.target_url, deps.scan_id, endpoints=endpoints)


def _commix_run(deps: ScanContext) -> List[dict]:
    return run_commix_scan(deps.target_url, deps.scan_id, param_urls=deps.discovered_params or None)


def _odat_run(deps: ScanContext) -> List[dict]:
    return run_odat_scan(deps.target_url, deps.scan_id)


# --- Eligibility predicates (the fingerprint gate) --------------------------------
# Each reads ctx.fingerprints and returns True only when the target actually presents
# the surface the tool attacks. Exploitation-tier tools default to ineligible, so an
# absent signal means the tool is never selected — never speculative.

def _eligible_jwt(ctx: ScanContext) -> bool:
    return bool((ctx.fingerprints or {}).get("has_jwt"))


def _eligible_graphql(ctx: ScanContext) -> bool:
    return bool((ctx.fingerprints or {}).get("graphql_endpoints"))


def _eligible_params(ctx: ScanContext) -> bool:
    # sqlmap / commix need a parameterised URL to inject into.
    fp = ctx.fingerprints or {}
    return bool(ctx.discovered_params or fp.get("param_urls"))


def _eligible_oracle(ctx: ScanContext) -> bool:
    return bool((ctx.fingerprints or {}).get("oracle_listener"))


def _eligible_basic_auth(ctx: ScanContext) -> bool:
    return (ctx.fingerprints or {}).get("auth_scheme") == "basic"


def _katana_done(deps: ScanContext, findings: List[dict]) -> str:
    return (f"katana complete — {len(deps.discovered_urls)} endpoint(s) discovered "
            f"({len(deps.discovered_params)} with parameters).")


def _ffuf_done(deps: ScanContext, findings: List[dict]) -> str:
    return f"ffuf complete — {len(deps.discovered_urls)} total endpoint(s) known."


def _arjun_done(deps: ScanContext, findings: List[dict]) -> str:
    return f"arjun complete — {len(deps.discovered_params)} parameterised URL(s) found."


SCANNERS = {
    "katana": Scanner("katana", "Crawl the target to discover endpoints and parameters",
                      _katana_run, "Crawling target to map attack surface...", _katana_done,
                      category="recon", tier="recon", technique_id="T1595.003"),
    "ffuf":   Scanner("ffuf", "Brute-force routes to discover unlinked endpoints",
                      _ffuf_run, "Brute-forcing routes with ffuf...", _ffuf_done,
                      category="recon", tier="recon", technique_id="T1595.003"),
    "arjun":  Scanner("arjun", "Discover hidden query parameters on known routes",
                      _arjun_run, "Discovering hidden parameters with arjun...", _arjun_done,
                      category="recon", tier="recon", technique_id="T1595.003"),
    "httpx":  Scanner("httpx", "Run httpx HTTP header probe against the target",
                      _httpx_run, "Running httpx HTTP header probe...",
                      category="recon", tier="recon", technique_id="T1595.002"),
    "nuclei": Scanner("nuclei", "Run Nuclei template scan (misconfigs, headers, CVEs) over discovered URLs",
                      _nuclei_run, "Running Nuclei template scan over discovered endpoints...",
                      category="vuln", tier="recon", technique_id="T1595.002"),
    "nikto":  Scanner("nikto", "Run nikto web server vulnerability scan",
                      _nikto_run, "Running nikto web server scan...",
                      category="vuln", tier="recon", technique_id="T1595.002"),
    "sqlmap": Scanner("sqlmap", "Run sqlmap SQL injection test over discovered parameterised URLs",
                      _sqlmap_run, "Running sqlmap SQL injection test on discovered parameters...",
                      category="backend", tier="exploit", technique_id="T1190",
                      eligible=_eligible_params),
    "hydra":  Scanner("hydra", "Run Hydra brute-force authentication check",
                      _hydra_run, "Running Hydra authentication checks...",
                      category="auth", tier="exploit", technique_id="T1110.001",
                      eligible=_eligible_basic_auth),
    # --- Intent-driven roster (headless CLI, grounded in HackTricks/MITRE/PTES) ---
    "jwt_tool": Scanner("jwt_tool", "Test JWTs for alg:none / weak-secret / key-confusion flaws",
                        _jwt_run, "Testing JWT for signature and algorithm weaknesses...",
                        category="auth", tier="exploit", technique_id="T1550.001",
                        eligible=_eligible_jwt),
    "graphql_cop": Scanner("graphql_cop", "Audit a GraphQL endpoint for introspection/DoS/injection misconfigs",
                           _graphql_cop_run, "Auditing GraphQL endpoint for misconfigurations...",
                           category="api", tier="exploit", technique_id="T1190",
                           eligible=_eligible_graphql),
    "commix": Scanner("commix", "Test discovered parameters for OS command injection",
                      _commix_run, "Testing parameters for command injection with commix...",
                      category="backend", tier="exploit", technique_id="T1059",
                      eligible=_eligible_params),
    "odat":   Scanner("odat", "Attack an exposed Oracle TNS listener (Oracle Database Attacking Tool)",
                      _odat_run, "Probing Oracle TNS listener with odat...",
                      category="backend", tier="exploit", technique_id="T1190",
                      eligible=_eligible_oracle),
}


async def _run_scanner(scanner: Scanner, deps: ScanContext, token: Any,
                       results: dict, sub_agent: Optional[str] = None) -> bool:
    """Execute one registry scanner's lifecycle against its sub-agent's delegated token.
    Records the finding count into ``results``. Returns True on success, False if ArmorIQ
    blocked the action (caller halts)."""
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": scanner.name, "status": "running",
        "message": scanner.running_message or f"Running {scanner.name}...",
        "subAgent": sub_agent,
    }})
    params = {"target": deps.target_url}
    try:
        await _armoriq_gate(deps.target_url, scanner.name, deps.target_url, params, token)
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps.broadcast, e, scanner.name)
        return False
    findings = await asyncio.to_thread(scanner.run, deps)
    # Audit the executed tool to the ArmorIQ dashboard under the delegated token (no-op in mock).
    await asyncio.to_thread(
        governance.report_tool, token, scanner.name, params,
        {"findings": len(findings)}, "success",
    )
    for f in findings:
        await deps.broadcast({"event": "finding_discovered", "data": f})
    done_msg = (scanner.done_message(deps, findings) if scanner.done_message
                else f"{scanner.name} complete — {len(findings)} finding(s).")
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": scanner.name, "status": "done", "message": done_msg, "subAgent": sub_agent,
    }})
    results[scanner.name] = len(findings)
    return True


# --- nmap (special-cased: findings come from async LLM interpretation) --------------

async def _interpret_nmap(scan: dict, scan_id: str) -> List[dict]:
    """Turn nmap's raw -sV output into Finding dicts using the LLM, in context (a message
    broker on :5000 differs from a dev server on :5000). Falls back to the deterministic
    port table if the LLM is unavailable or returns nothing, so findings are never lost."""
    ports = skip_standard_web_ports(scan.get("ports", []))
    raw = scan.get("raw", "")
    if not ports:
        return []

    # Build a lookup so LLM-returned port numbers map cleanly to a one-line evidence string
    # without falling back to raw nmap output (which includes filtered ports and noise).
    evidence_map = {p: f"Port: {p}/tcp open {s} {v}".rstrip() for p, s, v in ports}

    port_lines = "\n".join(f"  {p}/tcp open {s} {v}".rstrip() for p, s, v in ports)
    # Filter raw to only open-port lines — filtered/closed lines (e.g. 445/tcp filtered)
    # would bleed into LLM-generated finding descriptions if the full output were included.
    open_raw = "\n".join(
        line for line in raw.splitlines()
        if re.match(r"\d+/tcp\s+open\s+", line)
    )
    prompt = (
        "You are a penetration-test analyst classifying open TCP ports from an nmap -sV "
        "scan. For each open port, produce one finding with severity (Critical|High|Medium|"
        "Low), a short title, a description grounded in the detected service/version, and a "
        "concrete remediation. Judge risk in context — an intentionally-exposed application "
        "port behind no proxy is not automatically Critical, and do not give blanket "
        "'shut it down' advice for ports that are clearly part of the app's surface.\n\n"
        f"Open ports:\n{port_lines}\n\n"
        f"Open port scan lines:\n{open_raw}"
    )
    try:
        model = get_model().with_structured_output(NmapFindings)
        result = await model.ainvoke(prompt)
        assessments = getattr(result, "findings", None) or []
        if not assessments:
            return classify_ports_deterministic(ports, scan_id, raw)
        findings = []
        for a in assessments:
            ev = evidence_map.get(a.port)
            if not ev:
                # LLM returned a port not in our scan — skip to avoid hallucinated findings
                continue
            sev = a.severity if a.severity in ("Critical", "High", "Medium", "Low") else "Low"
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": sev,
                "title": a.title,
                "description": a.description,
                "remediation": a.remediation,
                "evidence": ev,
                "createdAt": datetime.utcnow().isoformat() + "Z",
            })
        return findings
    except Exception as e:
        print(f"[nmap] LLM interpretation failed, using deterministic fallback: {e}", flush=True)
        return classify_ports_deterministic(ports, scan_id, raw)


async def _run_nmap(deps: ScanContext, token: Any, sub_agent: str, results: dict) -> bool:
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": "nmap", "status": "running",
        "message": "Running Nmap -sV port scan...", "subAgent": sub_agent,
    }})
    params = {"target": deps.target_url}
    try:
        await _armoriq_gate(deps.target_url, "nmap", deps.target_url, params, token)
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps.broadcast, e, "nmap")
        return False
    scan = await asyncio.to_thread(run_nmap_scan, deps.target_url, deps.scan_id)
    findings = await _interpret_nmap(scan, deps.scan_id)
    await asyncio.to_thread(
        governance.report_tool, token, "nmap", params,
        {"findings": len(findings)}, "success",
    )
    for f in findings:
        await deps.broadcast({"event": "finding_discovered", "data": f})
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": "nmap", "status": "done",
        "message": f"nmap complete — {len(findings)} finding(s).", "subAgent": sub_agent,
    }})
    results["nmap"] = len(findings)
    return True


# --- Summary (LangChain) -----------------------------------------------------------

_SUMMARY_SYSTEM = (
    "You are ArmorGuard, an autonomous security analyst. Given the results of a completed "
    "vulnerability scan, write a concise 2-4 sentence executive summary of the target's "
    "security posture. Be factual; do not invent findings."
)


async def _summarize(deps: ScanContext, results: dict) -> Optional[str]:
    digest = ", ".join(f"{name}: {count} finding(s)" for name, count in results.items())
    prompt = (
        f"Target: {deps.target_url} ({deps.scan_mode} scan). "
        f"Attack surface discovered: {len(deps.discovered_urls)} endpoint(s), "
        f"{len(deps.discovered_params)} with parameters. "
        f"Tool results — {digest}. Summarise the security posture."
    )
    resp = await get_model().ainvoke([
        SystemMessage(content=_SUMMARY_SYSTEM),
        HumanMessage(content=prompt),
    ])
    text = (resp.content or "").strip() if hasattr(resp, "content") else str(resp).strip()
    return text or None


# --- Graph nodes -------------------------------------------------------------------

def _ctx(state: ScanState, broadcast) -> ScanContext:
    ctx = ScanContext(
        scan_id=state["scan_id"],
        target_url=state["target_url"],
        scan_mode=state["scan_mode"],
        selected_tools=state.get("tools", []),
        broadcast=broadcast,
        discovered_urls=list(state.get("discovered_urls", [])),
        discovered_params=list(state.get("discovered_params", [])),
        fingerprints=dict(state.get("fingerprints", {})),
    )
    return ctx


async def _node_orchestrator(state: ScanState, config) -> dict:
    """Mint the root intent token, then delegate a scoped token to each sub-agent."""
    broadcast = config["configurable"]["broadcast"]
    target_url = state["target_url"]
    await broadcast({"event": "scan_started", "data": {"scanId": state["scan_id"]}})

    tools = get_tools_for_mode(state["scan_mode"], state.get("selected_tools", []))
    plan = build_armoriq_plan(tools, target_url, state["scan_mode"])
    # The root policy must authorise every governed action the plan declares — including
    # the report sub-agent's `summarize`. Otherwise server-side enforce rejects summarize
    # as off-allow-list (policy_constraints_not_satisfied) and halts every clean scan at
    # the report phase. The drift demo still fires on genuinely off-policy actions.
    policy = build_armoriq_policy(tools + [REPORT_ACTION], target_url)

    plan_capture = await asyncio.to_thread(
        armoriq_client.capture_plan,
        LLM_PROVIDER, f"Perform a {state['scan_mode']} security scan of {target_url}", plan,
    )
    # Validity must comfortably exceed worst-case scan runtime so the token can't expire
    # mid-scan and surface a benign timeout as a false intent-drift halt.
    root_token = await asyncio.to_thread(
        armoriq_client.get_intent_token, plan_capture, policy, 900.0,
    )

    phases = group_tools_by_phase(tools)
    recon_tools = phases.get("recon", [])
    exploit_tools = phases.get("exploit", [])

    recon_token = (await asyncio.to_thread(
        governance.delegate, root_token, recon_tools, "armorguard-recon", target_url)
        if recon_tools else None)
    exploit_token = (await asyncio.to_thread(
        governance.delegate, root_token, exploit_tools, "armorguard-exploit", target_url)
        if exploit_tools else None)
    report_token = await asyncio.to_thread(
        governance.delegate, root_token, [REPORT_ACTION], "armorguard-report", target_url)

    return {
        "tools": tools,
        "phases": phases,
        "root_token": root_token,
        "recon_token": recon_token,
        "exploit_token": exploit_token,
        "report_token": report_token,
        "results": {},
        "discovered_urls": [],
        "discovered_params": [],
        "halted": False,
    }


async def _run_phase(state: ScanState, broadcast, phase: str, token: Any) -> dict:
    """Shared body for recon/exploit: run the phase's tools in order against the
    delegated token, threading the discovery surface through a ScanContext."""
    tools = state.get("phases", {}).get(phase, [])
    if not tools:
        return {}
    await broadcast({"event": "agent_reasoning", "data": {
        "text": f"[{phase}] Delegated token issued — running {', '.join(tools)}.",
    }})
    ctx = _ctx(state, broadcast)
    results = dict(state.get("results", {}))
    for name in tools:
        if name == "nmap":
            ok = await _run_nmap(ctx, token, phase, results)
        else:
            scanner = SCANNERS.get(name)
            if scanner is None:
                continue
            try:
                ok = await _run_scanner(scanner, ctx, token, results, sub_agent=phase)
            except Exception as e:
                # One tool failing must not abort the whole scan.
                await broadcast({"event": "tool_status", "data": {
                    "tool": name, "status": "done",
                    "message": f"{name} error: {e}", "subAgent": phase,
                }})
                results[name] = 0
                ok = True
        if not ok:
            return {
                "results": results,
                "discovered_urls": ctx.discovered_urls,
                "discovered_params": ctx.discovered_params,
                "halted": True,
            }
    return {
        "results": results,
        "discovered_urls": ctx.discovered_urls,
        "discovered_params": ctx.discovered_params,
    }


async def _node_recon(state: ScanState, config) -> dict:
    return await _run_phase(state, config["configurable"]["broadcast"], "recon", state.get("recon_token"))


async def _node_exploit(state: ScanState, config) -> dict:
    return await _run_phase(state, config["configurable"]["broadcast"], "exploit", state.get("exploit_token"))


async def _node_report(state: ScanState, config) -> dict:
    """Report sub-agent: synthesise the collected findings into an executive summary.

    The summary is the agent's OWN output to the user — not an external action against the
    target — so it is never gated/blocked by policy (the same way an assistant still answers
    you even when one of its tool calls is denied). Governance lives on the actual tool calls
    in recon/exploit. We still audit the report action for dashboard attribution, best-effort."""
    broadcast = config["configurable"]["broadcast"]
    token = state.get("report_token")
    target_url = state["target_url"]
    await broadcast({"event": "agent_reasoning", "data": {
        "text": "[report] Delegated token issued — synthesising findings into an executive summary.",
    }})

    ctx = _ctx(state, broadcast)
    try:
        summary = await _summarize(ctx, state.get("results", {}))
        if summary:
            await broadcast({"event": "agent_reasoning", "data": {"text": summary}})
            # Separate durable event so _persist_event can write the summary to the scan
            # row, making it available via _replay_snapshot and /report for reconnecting clients.
            await broadcast({"event": "scan_summary", "data": {"text": summary}})
        # Attribute the report step on the ArmorIQ dashboard (audit only — never enforces).
        await asyncio.to_thread(
            governance.report_tool, token, REPORT_ACTION,
            {"target": target_url}, {"summarised": bool(summary)}, "success",
        )
    except Exception as e:
        print(f"SUMMARIZE FAILED WITH EXCEPTION: {e}", flush=True)
        traceback.print_exc()
    return {}


async def _node_finalize(state: ScanState, config) -> dict:
    """Reached only when no sub-agent halted: mark the plan complete + signal success."""
    broadcast = config["configurable"]["broadcast"]
    root_token = state.get("root_token")
    if root_token is not None:
        await asyncio.to_thread(governance.complete, root_token.plan_id)
    await broadcast({"event": "scan_completed", "data": {"scanId": state["scan_id"]}})
    return {}


def _route_after_phase(state: ScanState) -> str:
    return "halt" if state.get("halted") else "continue"


# =====================================================================================
# Intent-driven pipeline: Fingerprint → Select → Attack → Confirm → Report
# Runs when scan_mode == "autonomous". Reuses the ArmorIQ gate, delegated tokens, and
# scanner registry; the difference is the agent *chooses* which eligible tools to run
# (Select) and reports only findings it can *prove* (Confirm).
# =====================================================================================

# Canonical run order when Select can't/needn't reorder (broad checks before targeted).
_ATTACK_ORDER = [
    "nuclei", "nikto", "sqlmap", "commix", "jwt_tool", "graphql_cop", "odat", "hydra",
]

_SELECT_SYSTEM = (
    "You are ArmorGuard's exploitation strategist. Given a target fingerprint and a "
    "retrieved pentest playbook (HackTricks / MITRE ATT&CK / PTES), choose which of the "
    "ELIGIBLE tools to run and in what order to prove real vulnerabilities on THIS target. "
    "Only choose tools from the eligible list. For each, give a one-line rationale tied to "
    "the fingerprint and the MITRE technique id. Prefer broad checks before targeted "
    "exploits. Do not invent tools or targets."
)


def _eligible_attack_tools(ctx: ScanContext) -> List[str]:
    """The subset of the autonomous attack roster warranted for this target: recon-tier
    attack tools (nuclei/nikto) are always eligible; exploit-tier tools must pass their
    fingerprint gate."""
    eligible = []
    for name in _ATTACK_ORDER:
        scanner = SCANNERS.get(name)
        if scanner is None:
            continue
        if scanner.is_eligible(ctx):
            eligible.append(name)
    return eligible


async def _node_orchestrator_intent(state: ScanState, config) -> dict:
    """Autonomous orchestrator: mint the root token and delegate fingerprint/attack/report
    scoped tokens. The attack token is scoped to the whole eligible roster up front so the
    Select phase can pick any of them without a server-side allow-list miss."""
    broadcast = config["configurable"]["broadcast"]
    target_url = state["target_url"]
    await broadcast({"event": "scan_started", "data": {"scanId": state["scan_id"]}})

    tools = get_tools_for_mode("autonomous", [])
    plan = build_armoriq_plan(tools, target_url, "autonomous")
    policy = build_armoriq_policy(tools + [REPORT_ACTION], target_url)

    plan_capture = await asyncio.to_thread(
        armoriq_client.capture_plan,
        LLM_PROVIDER, f"Perform an autonomous, intent-driven security scan of {target_url}", plan,
    )
    root_token = await asyncio.to_thread(
        armoriq_client.get_intent_token, plan_capture, policy, 1200.0,
    )

    phases = group_tools_autonomous(tools)
    fingerprint_tools = phases.get("fingerprint", [])
    attack_tools = phases.get("attack", [])

    fingerprint_token = (await asyncio.to_thread(
        governance.delegate, root_token, fingerprint_tools, "armorguard-fingerprint", target_url)
        if fingerprint_tools else None)
    attack_token = (await asyncio.to_thread(
        governance.delegate, root_token, attack_tools, "armorguard-attack", target_url)
        if attack_tools else None)
    report_token = await asyncio.to_thread(
        governance.delegate, root_token, [REPORT_ACTION], "armorguard-report", target_url)

    return {
        "tools": tools,
        "phases": phases,
        "root_token": root_token,
        # Stored under the deterministic-pipeline names so _run_scanner/_armoriq_gate reuse
        # them unchanged: fingerprint↦recon_token, attack+confirm↦exploit_token.
        "recon_token": fingerprint_token,
        "exploit_token": attack_token,
        "report_token": report_token,
        "results": {},
        "discovered_urls": [],
        "discovered_params": [],
        "fingerprints": {},
        "attack_plan": [],
        "findings": [],
        "halted": False,
    }


async def _node_fingerprint(state: ScanState, config) -> dict:
    """Probe the target and derive structured signals. Emits no findings — raw observations
    are context for Select, not vulnerabilities. Gated through ArmorIQ (representative
    'nmap' action) so the scope backstop still halts an off-scope / injected target."""
    broadcast = config["configurable"]["broadcast"]
    token = state.get("recon_token")
    target_url = state["target_url"]
    await broadcast({"event": "agent_reasoning", "data": {
        "text": "[fingerprint] Probing target — ports, tech stack, auth scheme, endpoints.",
    }})
    await broadcast({"event": "tool_status", "data": {
        "tool": "fingerprint", "status": "running",
        "message": "Fingerprinting attack surface...", "subAgent": "fingerprint",
    }})
    try:
        await _armoriq_gate(target_url, "nmap", target_url, {"target": target_url}, token)
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(broadcast, e, "fingerprint")
        return {"halted": True}

    fp = await asyncio.to_thread(fp_mod.build_fingerprint, target_url, state["scan_id"])
    await asyncio.to_thread(
        governance.report_tool, token, "nmap", {"target": target_url},
        {"signals": len(fp)}, "success",
    )
    summary = fp_mod.summarize_fingerprint(fp)
    await broadcast({"event": "fingerprint_complete", "data": {
        "server": fp.get("server"), "tech": fp.get("tech"),
        "authScheme": fp.get("auth_scheme"), "hasJwt": fp.get("has_jwt"),
        "graphqlEndpoints": fp.get("graphql_endpoints"), "javaMarkers": fp.get("java_markers"),
        "oracleListener": fp.get("oracle_listener"),
        "openPorts": fp.get("open_ports"),
        "endpointCount": len(fp.get("endpoints", [])),
        "paramCount": len(fp.get("param_urls", [])),
    }})
    await broadcast({"event": "agent_reasoning", "data": {"text": f"[fingerprint] {summary}"}})
    await broadcast({"event": "tool_status", "data": {
        "tool": "fingerprint", "status": "done",
        "message": f"Fingerprint complete — {summary}", "subAgent": "fingerprint",
    }})
    return {
        "fingerprints": fp,
        "discovered_urls": fp.get("endpoints", []),
        "discovered_params": fp.get("param_urls", []),
    }


def _select_query(fp: dict) -> str:
    parts = ["Exploit public-facing application"]
    if fp.get("tech"):
        parts.append("stack: " + ", ".join(fp["tech"]))
    parts.append(f"auth: {fp.get('auth_scheme', 'none')}")
    if fp.get("has_jwt"):
        parts.append("JWT token forgery")
    if fp.get("graphql_endpoints"):
        parts.append("GraphQL introspection and injection")
    if fp.get("java_markers"):
        parts.append("Java deserialization")
    if fp.get("oracle_listener"):
        parts.append("Oracle TNS listener attack")
    if fp.get("param_urls"):
        parts.append("SQL and command injection in parameters")
    return "; ".join(parts)


async def _node_select(state: ScanState, config) -> dict:
    """Consult the RAG playbook and pick the eligible tools to run against THIS target.
    Deterministic eligibility is authoritative; the LLM only orders/justifies within it,
    with a deterministic fallback so Select never fails the scan."""
    broadcast = config["configurable"]["broadcast"]
    ctx = _ctx(state, broadcast)
    fp = ctx.fingerprints

    eligible = _eligible_attack_tools(ctx)
    await broadcast({"event": "agent_reasoning", "data": {
        "text": f"[select] Eligible tools for this surface: {', '.join(eligible) or 'none'}.",
    }})
    if not eligible:
        return {"attack_plan": []}

    # Retrieve grounded playbook context (best-effort; empty if KB not ingested).
    chunks = await asyncio.to_thread(
        kb.retrieve, _select_query(fp), "Exploitation",
        None, 6,
    )
    playbook = kb.format_playbook(chunks)
    if chunks:
        await broadcast({"event": "agent_reasoning", "data": {
            "text": f"[select] Retrieved {len(chunks)} playbook ent(ies) from HackTricks/MITRE/PTES.",
        }})

    plan_steps: List[dict] = []
    try:
        prompt = (
            f"Target fingerprint:\n"
            f"  tech: {fp.get('tech')}\n  auth: {fp.get('auth_scheme')} (jwt={fp.get('has_jwt')})\n"
            f"  graphql: {fp.get('graphql_endpoints')}\n  java: {fp.get('java_markers')}\n"
            f"  oracle: {fp.get('oracle_listener')}\n"
            f"  parameterised URLs: {len(fp.get('param_urls', []))}\n\n"
            f"ELIGIBLE tools (choose only from these): {eligible}\n\n"
            f"Playbook context:\n{playbook}\n\n"
            "Return an ordered attack plan (tool, rationale, technique_id)."
        )
        model = get_model().with_structured_output(AttackPlan)
        result = await model.ainvoke([
            SystemMessage(content=_SELECT_SYSTEM), HumanMessage(content=prompt),
        ])
        for step in (getattr(result, "steps", None) or []):
            if step.tool in eligible and step.tool not in [s["tool"] for s in plan_steps]:
                plan_steps.append({
                    "tool": step.tool,
                    "rationale": step.rationale,
                    "techniqueId": step.technique_id or SCANNERS[step.tool].technique_id,
                })
    except Exception as e:
        print(f"[select] LLM planning failed, using deterministic fallback: {e}", flush=True)

    # Fallback / completion: ensure every eligible tool is represented, in canonical order.
    planned = {s["tool"] for s in plan_steps}
    for name in eligible:
        if name not in planned:
            plan_steps.append({
                "tool": name,
                "rationale": f"{SCANNERS[name].description} — warranted by fingerprint.",
                "techniqueId": SCANNERS[name].technique_id,
            })

    for s in plan_steps:
        await broadcast({"event": "agent_reasoning", "data": {
            "text": f"[select] → {s['tool']} ({s['techniqueId']}): {s['rationale']}",
        }})
    return {"attack_plan": plan_steps}


async def _run_attack_tool(scanner: Scanner, deps: ScanContext, token: Any,
                           results: dict, collected: List[dict]) -> bool:
    """Like _run_scanner but *collects* findings instead of broadcasting them — in the
    intent pipeline nothing is reported until the Confirm phase proves it. Returns False
    only on an ArmorIQ block (caller halts)."""
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": scanner.name, "status": "running",
        "message": scanner.running_message or f"Running {scanner.name}...",
        "subAgent": "attack",
    }})
    params = {"target": deps.target_url}
    try:
        await _armoriq_gate(deps.target_url, scanner.name, deps.target_url, params, token)
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps.broadcast, e, scanner.name)
        return False
    findings = await asyncio.to_thread(scanner.run, deps)
    await asyncio.to_thread(
        governance.report_tool, token, scanner.name, params,
        {"candidates": len(findings)}, "success",
    )
    # Tag each candidate with the producing tool's MITRE technique so Confirm/Report can
    # carry it into the persisted finding without re-deriving it.
    for f in findings:
        f.setdefault("attackTechniqueId", scanner.technique_id)
    collected.extend(findings)
    results[scanner.name] = len(findings)
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": scanner.name, "status": "done",
        "message": f"{scanner.name} complete — {len(findings)} candidate(s) to verify.",
        "subAgent": "attack",
    }})
    return True


async def _node_attack(state: ScanState, config) -> dict:
    """Run the Select-chosen tools, collecting candidate findings (not yet reported)."""
    broadcast = config["configurable"]["broadcast"]
    token = state.get("exploit_token")
    plan = state.get("attack_plan", [])
    if not plan:
        await broadcast({"event": "agent_reasoning", "data": {
            "text": "[attack] No eligible tools selected — nothing to run.",
        }})
        return {"findings": [], "results": dict(state.get("results", {}))}

    ctx = _ctx(state, broadcast)
    results = dict(state.get("results", {}))
    collected: List[dict] = list(state.get("findings", []))
    for step in plan:
        name = step["tool"]
        scanner = SCANNERS.get(name)
        if scanner is None or not scanner.is_eligible(ctx):
            continue
        try:
            ok = await _run_attack_tool(scanner, ctx, token, results, collected)
        except Exception as e:
            await broadcast({"event": "tool_status", "data": {
                "tool": name, "status": "done",
                "message": f"{name} error: {e}", "subAgent": "attack",
            }})
            results[name] = 0
            ok = True
        if not ok:
            return {"findings": collected, "results": results,
                    "discovered_urls": ctx.discovered_urls,
                    "discovered_params": ctx.discovered_params, "halted": True}
    return {"findings": collected, "results": results,
            "discovered_urls": ctx.discovered_urls,
            "discovered_params": ctx.discovered_params}


async def _node_confirm(state: ScanState, config) -> dict:
    """Prove each candidate with an active PoC; report only the confirmed ones."""
    broadcast = config["configurable"]["broadcast"]
    token = state.get("exploit_token")
    target_url = state["target_url"]
    candidates = state.get("findings", [])
    await broadcast({"event": "agent_reasoning", "data": {
        "text": f"[confirm] Verifying {len(candidates)} candidate finding(s) with active PoC.",
    }})
    verify_ctx = {"fingerprints": state.get("fingerprints", {})}
    # findingType → the allow-listed tool the active PoC re-runs (for the ArmorIQ gate).
    _gate_action = {"sql_injection": "sqlmap", "command_injection": "commix", "jwt": "jwt_tool"}

    confirmed_count = 0
    results = dict(state.get("results", {}))
    # Built up alongside the loop and returned as the new `findings` state — without this,
    # the confirmed/evidence updates only ever lived on a local copy broadcast over the
    # WebSocket, and the next node (_node_report_intent) would read the original, still-
    # unconfirmed `candidates` list and wrongly conclude nothing was proven.
    updated_findings: list = []
    for finding in candidates:
        ftype = finding.get("findingType", "")
        action = _gate_action.get(ftype)
        if action:  # active re-test hits the target — gate it
            try:
                await _armoriq_gate(target_url, action, target_url, {"target": target_url}, token)
            except (PolicyBlockedException, IntentMismatchException) as e:
                await _handle_armoriq_block(broadcast, e, f"confirm:{action}")
                return {"halted": True, "results": results, "findings": updated_findings + candidates[len(updated_findings):]}

        confirmed, proof = await asyncio.to_thread(
            confirm_finding, finding, target_url, verify_ctx,
        )
        if confirmed:
            confirmed_count += 1
            finding = dict(finding)
            finding["confirmed"] = True
            base_ev = finding.get("evidence") or ""
            finding["evidence"] = (base_ev + f"\n\n[PROOF] {proof}").strip()
            updated_findings.append(finding)
            # Only now is the finding emitted → persisted → shown in the report.
            await broadcast({"event": "finding_discovered", "data": finding})
            await broadcast({"event": "agent_reasoning", "data": {
                "text": f"[confirm] ✔ Proven: {finding.get('title')} — {proof[:160]}",
            }})
        else:
            updated_findings.append(finding)
            await broadcast({"event": "agent_reasoning", "data": {
                "text": f"[confirm] unconfirmed, demoted: {finding.get('title')} — {proof[:120]}",
            }})
    results["confirmed"] = confirmed_count
    await broadcast({"event": "tool_status", "data": {
        "tool": "confirm", "status": "done",
        "message": f"Confirm complete — {confirmed_count}/{len(candidates)} proven.",
        "subAgent": "confirm",
    }})
    return {"results": results, "findings": updated_findings}


async def _node_report_intent(state: ScanState, config) -> dict:
    """Summarise the *proven* findings, tagged with their MITRE techniques."""
    broadcast = config["configurable"]["broadcast"]
    token = state.get("report_token")
    target_url = state["target_url"]
    proven = [f for f in state.get("findings", []) if f.get("confirmed")]
    await broadcast({"event": "agent_reasoning", "data": {
        "text": "[report] Synthesising an executive summary of proven vulnerabilities.",
    }})
    ctx = _ctx(state, broadcast)
    try:
        if proven:
            digest = "; ".join(
                f"{f.get('title')} [{f.get('severity')}]" for f in proven
            )
            prompt = (
                f"Target: {target_url} (autonomous intent-driven scan). "
                f"{len(proven)} vulnerabilities were actively PROVEN with evidence of access: "
                f"{digest}. Write a 2-4 sentence executive summary of the confirmed risk."
            )
            resp = await get_model().ainvoke([
                SystemMessage(content=_SUMMARY_SYSTEM), HumanMessage(content=prompt),
            ])
            summary = (resp.content or "").strip() if hasattr(resp, "content") else str(resp).strip()
        else:
            summary = (f"No vulnerabilities could be actively proven on {target_url}. The "
                       "attack surface was fingerprinted and eligible exploits were attempted, "
                       "but none produced verified evidence of access.")
        if summary:
            await broadcast({"event": "agent_reasoning", "data": {"text": summary}})
            await broadcast({"event": "scan_summary", "data": {"text": summary}})
        await asyncio.to_thread(
            governance.report_tool, token, REPORT_ACTION,
            {"target": target_url}, {"proven": len(proven)}, "success",
        )
    except Exception as e:
        print(f"INTENT REPORT FAILED: {e}", flush=True)
        traceback.print_exc()
    return {}


# --- Graph construction (compiled once) --------------------------------------------

def _build_graph():
    builder = StateGraph(ScanState)
    builder.add_node("orchestrator", _node_orchestrator)
    builder.add_node("recon", _node_recon)
    builder.add_node("exploit", _node_exploit)
    builder.add_node("report", _node_report)
    builder.add_node("finalize", _node_finalize)

    builder.add_edge(START, "orchestrator")
    builder.add_edge("orchestrator", "recon")
    builder.add_conditional_edges("recon", _route_after_phase, {"continue": "exploit", "halt": END})
    builder.add_conditional_edges("exploit", _route_after_phase, {"continue": "report", "halt": END})
    builder.add_conditional_edges("report", _route_after_phase, {"continue": "finalize", "halt": END})
    builder.add_edge("finalize", END)
    return builder.compile()


def _build_intent_graph():
    """The intent-driven pipeline used by scan_mode == 'autonomous':
    orchestrator → fingerprint → select → attack → confirm → report → finalize.
    Halt-on-block routing is shared with the deterministic graph via _route_after_phase."""
    builder = StateGraph(ScanState)
    builder.add_node("orchestrator", _node_orchestrator_intent)
    builder.add_node("fingerprint", _node_fingerprint)
    builder.add_node("select", _node_select)
    builder.add_node("attack", _node_attack)
    builder.add_node("confirm", _node_confirm)
    builder.add_node("report", _node_report_intent)
    builder.add_node("finalize", _node_finalize)

    builder.add_edge(START, "orchestrator")
    builder.add_edge("orchestrator", "fingerprint")
    builder.add_conditional_edges("fingerprint", _route_after_phase, {"continue": "select", "halt": END})
    # Select never touches the target, so it can't halt — always proceed to attack.
    builder.add_edge("select", "attack")
    builder.add_conditional_edges("attack", _route_after_phase, {"continue": "confirm", "halt": END})
    builder.add_conditional_edges("confirm", _route_after_phase, {"continue": "report", "halt": END})
    builder.add_conditional_edges("report", _route_after_phase, {"continue": "finalize", "halt": END})
    builder.add_edge("finalize", END)
    return builder.compile()


_graph = _build_graph()
_intent_graph = _build_intent_graph()


async def run_scan(
    scan_id: str,
    target_url: str,
    scan_mode: str,
    selected_tools: list,
    broadcast,
) -> None:
    """Run the scan as a governed LangGraph pipeline.

    Two pipelines, selected by ``scan_mode``:
      * "autonomous" → the intent-driven loop (Fingerprint → Select → Attack → Confirm →
        Report). The agent fingerprints the target, an LLM consults the RAG playbook to
        select eligible tools, and only actively-proven vulnerabilities are reported.
      * everything else (default/deep/custom) → the deterministic recon → exploit → report
        pipeline. Tool order is fixed so discovery output reaches the attack tools; the LLM
        only interprets nmap output and summarises. This path powers the intent-drift demo.
    """
    initial: ScanState = {
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "selected_tools": list(selected_tools or []),
        "discovered_urls": [],
        "discovered_params": [],
        "results": {},
        "fingerprints": {},
        "attack_plan": [],
        "findings": [],
        "halted": False,
    }
    graph = _intent_graph if scan_mode == "autonomous" else _graph
    try:
        await graph.ainvoke(initial, config={"configurable": {"broadcast": broadcast}})
    except Exception as e:
        traceback.print_exc()
        await broadcast({"event": "scan_failed", "data": {"reason": str(e)}})
