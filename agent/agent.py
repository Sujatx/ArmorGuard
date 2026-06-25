import asyncio
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
from agent.governance.armoriq_client import client as armoriq_client, governance
from agent.governance.policies import (
    get_tools_for_mode, build_armoriq_plan, build_armoriq_policy,
    group_tools_by_phase, REPORT_ACTION,
)
from agent.tools.nmap_tool import run_nmap_scan, classify_ports_deterministic
from agent.tools.katana_tool import run_katana_crawl
from agent.tools.ffuf_tool import run_ffuf_scan
from agent.tools.arjun_tool import run_arjun_scan
from agent.tools.nuclei_tool import run_nuclei_scan
from agent.tools.nikto_tool import run_nikto_scan
from agent.tools.httpx_tool import run_httpx_scan
from agent.tools.sqlmap_tool import run_sqlmap_scan
from agent.tools.hydra_tool import run_hydra_scan


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

    valid = await asyncio.to_thread(armoriq_client.verify_token, token)
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


def _katana_done(deps: ScanContext, findings: List[dict]) -> str:
    return (f"katana complete — {len(deps.discovered_urls)} endpoint(s) discovered "
            f"({len(deps.discovered_params)} with parameters).")


def _ffuf_done(deps: ScanContext, findings: List[dict]) -> str:
    return f"ffuf complete — {len(deps.discovered_urls)} total endpoint(s) known."


def _arjun_done(deps: ScanContext, findings: List[dict]) -> str:
    return f"arjun complete — {len(deps.discovered_params)} parameterised URL(s) found."


SCANNERS = {
    "katana": Scanner("katana", "Crawl the target to discover endpoints and parameters",
                      _katana_run, "Crawling target to map attack surface...", _katana_done),
    "ffuf":   Scanner("ffuf", "Brute-force routes to discover unlinked endpoints",
                      _ffuf_run, "Brute-forcing routes with ffuf...", _ffuf_done),
    "arjun":  Scanner("arjun", "Discover hidden query parameters on known routes",
                      _arjun_run, "Discovering hidden parameters with arjun...", _arjun_done),
    "httpx":  Scanner("httpx", "Run httpx HTTP header probe against the target",
                      _httpx_run, "Running httpx HTTP header probe..."),
    "nuclei": Scanner("nuclei", "Run Nuclei template scan (misconfigs, headers, CVEs) over discovered URLs",
                      _nuclei_run, "Running Nuclei template scan over discovered endpoints..."),
    "nikto":  Scanner("nikto", "Run nikto web server vulnerability scan",
                      _nikto_run, "Running nikto web server scan..."),
    "sqlmap": Scanner("sqlmap", "Run sqlmap SQL injection test over discovered parameterised URLs",
                      _sqlmap_run, "Running sqlmap SQL injection test on discovered parameters..."),
    "hydra":  Scanner("hydra", "Run Hydra brute-force authentication check",
                      _hydra_run, "Running Hydra authentication checks..."),
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
    ports = scan.get("ports", [])
    raw = scan.get("raw", "")
    if not ports:
        return []

    port_lines = "\n".join(f"  {p}/tcp open {s} {v}".rstrip() for p, s, v in ports)
    prompt = (
        "You are a penetration-test analyst classifying open TCP ports from an nmap -sV "
        "scan. For each open port, produce one finding with severity (Critical|High|Medium|"
        "Low), a short title, a description grounded in the detected service/version, and a "
        "concrete remediation. Judge risk in context — an intentionally-exposed application "
        "port behind no proxy is not automatically Critical, and do not give blanket "
        "'shut it down' advice for ports that are clearly part of the app's surface.\n\n"
        f"Open ports:\n{port_lines}\n\n"
        f"Raw nmap output:\n{raw[:4000]}"
    )
    try:
        model = get_model().with_structured_output(NmapFindings)
        result = await model.ainvoke(prompt)
        assessments = getattr(result, "findings", None) or []
        if not assessments:
            return classify_ports_deterministic(ports, scan_id, raw)
        findings = []
        for a in assessments:
            sev = a.severity if a.severity in ("Critical", "High", "Medium", "Low") else "Low"
            evidence = next(
                (f"Port: {p}/tcp open {s} {v}".rstrip() for p, s, v in ports if p == a.port),
                raw[:500],
            )
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": sev,
                "title": a.title,
                "description": a.description,
                "remediation": a.remediation,
                "evidence": evidence,
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


_graph = _build_graph()


async def run_scan(
    scan_id: str,
    target_url: str,
    scan_mode: str,
    selected_tools: list,
    broadcast,
) -> None:
    """Run the scan as a governed LangGraph pipeline: an orchestrator mints a root intent
    token and delegates a scoped token to each of three deterministic sub-agents
    (recon → exploit → report). Tools execute in their phase's defined order so discovery
    output reliably reaches the attack tools; the LLM is used only to interpret nmap output
    and to summarise — never to orchestrate — keeping ordering deterministic.
    """
    initial: ScanState = {
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "selected_tools": list(selected_tools or []),
        "discovered_urls": [],
        "discovered_params": [],
        "results": {},
        "halted": False,
    }
    try:
        await _graph.ainvoke(initial, config={"configurable": {"broadcast": broadcast}})
    except Exception as e:
        traceback.print_exc()
        await broadcast({"event": "scan_failed", "data": {"reason": str(e)}})
