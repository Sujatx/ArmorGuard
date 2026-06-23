import asyncio
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional
from agent.tools.hydra_tool import run_hydra_scan

from pydantic_ai import Agent, RunContext
from armoriq_sdk import PolicyBlockedException, IntentMismatchException

from agent.config import (
    LLM_PROVIDER,
    GEMINI_API_KEY, GROQ_API_KEY, CLAUDE_API_KEY,
    OLLAMA_BASE_URL, OLLAMA_MODEL,
)
from agent.governance.armoriq_client import client as armoriq_client, governance
from agent.governance.policies import (
    get_tools_for_mode, build_armoriq_plan, build_armoriq_policy,
)
from agent.tools.nmap_tool import run_nmap_scan
from agent.tools.katana_tool import run_katana_crawl
from agent.tools.ffuf_tool import run_ffuf_scan
from agent.tools.arjun_tool import run_arjun_scan
from agent.tools.nuclei_tool import run_nuclei_scan
from agent.tools.nikto_tool import run_nikto_scan
from agent.tools.httpx_tool import run_httpx_scan
from agent.tools.sqlmap_tool import run_sqlmap_scan


class AgentHaltedException(Exception):
    pass


@dataclass
class ScanContext:
    scan_id: str
    target_url: str
    scan_mode: str
    selected_tools: List[str]
    broadcast: Any
    intent_token: Any = field(default=None)
    # Attack surface mapped by the discovery stage (katana) and consumed by the attack
    # tools (nuclei, sqlmap). Defaults to just the base target until discovery runs.
    discovered_urls: List[str] = field(default_factory=list)
    discovered_params: List[str] = field(default_factory=list)


_SYSTEM_PROMPT = (
    "You are ArmorGuard, an autonomous AI security scanning agent. "
    "Your mission is to systematically identify vulnerabilities on the approved target "
    "using only the tools provided. Execute each tool exactly once in the specified order. "
    "After each tool completes, briefly summarise what was found before proceeding. "
    "Never deviate from the approved target or tool list."
)


def _key(val: str) -> Optional[str]:
    return val if (val and "placeholder" not in val) else None


def _build_model():
    if LLM_PROVIDER == "groq":
        from pydantic_ai.models.groq import GroqModel
        from pydantic_ai.providers.groq import GroqProvider
        return GroqModel("llama-3.3-70b-versatile", provider=GroqProvider(api_key=_key(GROQ_API_KEY)))
    elif LLM_PROVIDER in ("anthropic", "claude"):
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider
        return AnthropicModel("claude-sonnet-4-6", provider=AnthropicProvider(api_key=_key(CLAUDE_API_KEY)))
    elif LLM_PROVIDER == "ollama":
        from pydantic_ai.models.openai import OpenAIModel
        from pydantic_ai.providers.openai import OpenAIProvider
        return OpenAIModel(
            OLLAMA_MODEL,
            provider=OpenAIProvider(base_url=f"{OLLAMA_BASE_URL}/v1", api_key="ollama"),
        )
    else:  # gemini (default)
        from pydantic_ai.models.gemini import GeminiModel
        from pydantic_ai.providers.google import GoogleProvider
        return GeminiModel("gemini-2.0-flash", provider=GoogleProvider(api_key=_key(GEMINI_API_KEY)))


async def _handle_armoriq_block(deps: ScanContext, exc: Exception, attempted_action: str) -> None:
    meta = getattr(exc, "metadata", {}) or {}
    drift_class = meta.get("drift_classification", "prompt_injection")
    error_code = getattr(exc, "reason", "blocked")
    
    # [ArmorGuard AI Rewrite] - Only coerce out_of_scope_target to hallucination if it's 
    # NOT already explicitly tagged as prompt_injection. The demo prompt injection 
    # uses an out of scope target, so we must preserve its classification.
    if error_code == "out_of_scope_target" and drift_class != "prompt_injection":
        drift_class = "hallucination"
        
    matched_policy = meta.get("matched_policy") or meta.get("matchedPolicy")
    await deps.broadcast({"event": "intent_drift_detected", "data": {
        "errorCode": error_code,
        "blockReason": str(exc),
        "driftClassification": drift_class,
        "attemptedAction": attempted_action,
        "matchedPolicy": matched_policy,
    }})
    await deps.broadcast({"event": "agent_halted", "data": {
        "reason": f"ArmorIQ blocked {attempted_action}: {error_code}",
    }})


async def _armoriq_gate(deps: "ScanContext", action: str, target: str,
                        params: Optional[dict] = None,
                        token: Any = None) -> None:
    """Gate a tool call through ArmorIQ before it runs.

    Three layers, in order:
      1. token validity (expiry) — a benign timeout, not drift.
      2. deterministic scope backstop — blocks any off-scope target locally so the
         prompt-injection demo halts even when no dashboard policy is configured.
      3. real ArmorIQ enforcement (``governance.enforce`` → ``/iap/sdk/enforce``) —
         server-side allow/block/hold against the dashboard policy.

    ``token`` defaults to the scan's root token; sub-agents pass their own delegated
    token so enforcement is scoped to the phase the sub-agent is allowed to run."""
    token = token if token is not None else deps.intent_token
    params = params if params is not None else {"target": target}

    valid = await asyncio.to_thread(armoriq_client.verify_token, token)
    if not valid:
        raise IntentMismatchException(
            f"Intent token expired before {action}",
            action=action,
        )

    # Deterministic local backstop — independent of any dashboard policy.
    approved = deps.target_url.rstrip("/")
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
        raise PolicyBlockedException(
            decision.reason or f"ArmorIQ {decision.action} on {action}",
            reason=decision.reason or decision.action,
            metadata={
                "drift_classification": "prompt_injection",
                "matched_policy": decision.matched_policy,
            },
        )


# --- Scanner registry -------------------------------------------------------------
# Each scanner declares how to run and how to describe itself; the generic runner
# (`_run_scanner`) handles the identical lifecycle every tool used to copy-paste:
# broadcast "running" → ArmorIQ gate → execute in a thread → stream findings →
# broadcast "done". Adding a tool = one Scanner entry, not another 20-line wrapper.

@dataclass
class Scanner:
    name: str
    description: str                       # shown to the LLM as the tool description
    run: Callable[[ScanContext], List[dict]]   # sync; executed via asyncio.to_thread
    running_message: str = ""
    # Optional custom "done" message (e.g. discovery reports endpoint counts, not findings).
    done_message: Optional[Callable[[ScanContext, List[dict]], str]] = None


# --- Per-scanner adapters: bridge the registry to the underlying tool functions and
# wire the shared discovery state (read/write ScanContext.discovered_*). -----------

def _nmap_run(deps: ScanContext) -> List[dict]:
    return run_nmap_scan(deps.target_url, deps.scan_id)


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
    # Merge brute-forced routes into whatever katana already crawled.
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
    return run_hydra_scan(
        deps.target_url,
        deps.scan_id
    )


def _katana_done(deps: ScanContext, findings: List[dict]) -> str:
    return (f"katana complete — {len(deps.discovered_urls)} endpoint(s) discovered "
            f"({len(deps.discovered_params)} with parameters).")


def _ffuf_done(deps: ScanContext, findings: List[dict]) -> str:
    return f"ffuf complete — {len(deps.discovered_urls)} total endpoint(s) known."


def _arjun_done(deps: ScanContext, findings: List[dict]) -> str:
    return f"arjun complete — {len(deps.discovered_params)} parameterised URL(s) found."


SCANNERS = {
    "nmap":   Scanner("nmap", "Run Nmap TCP port scan against the target",
                      _nmap_run, "Running Nmap TCP port scan..."),
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


async def _run_scanner(scanner: Scanner, deps: ScanContext) -> int:
    """Execute one scanner's full lifecycle: broadcast running → ArmorIQ gate →
    run in a thread → stream findings → broadcast done. Returns the finding count.
    Raises AgentHaltedException if ArmorIQ blocks the action."""
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": scanner.name, "status": "running",
        "message": scanner.running_message or f"Running {scanner.name}...",
    }})
    token = deps.intent_token
    params = {"target": deps.target_url}
    try:
        await _armoriq_gate(deps, scanner.name, deps.target_url, params, token)
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps, e, scanner.name)
        raise AgentHaltedException(str(e))
    findings = await asyncio.to_thread(scanner.run, deps)
    # Audit the executed tool to the ArmorIQ dashboard (no-op in mock mode).
    await asyncio.to_thread(
        governance.report_tool, token, scanner.name, params,
        {"findings": len(findings)}, "success",
    )
    for f in findings:
        await deps.broadcast({"event": "finding_discovered", "data": f})
    done_msg = (scanner.done_message(deps, findings) if scanner.done_message
                else f"{scanner.name} complete — {len(findings)} finding(s).")
    await deps.broadcast({"event": "tool_status", "data": {
        "tool": scanner.name, "status": "done", "message": done_msg,
    }})
    return len(findings)


# Model is built once, after the .env is loaded by the backend process.
_model = None


def _get_model():
    global _model
    if _model is None:
        _model = _build_model()
    return _model


_summary_agent: Optional[Agent] = None


def _get_summary_agent() -> Agent:
    """A tool-less agent used only to turn the scan results into a short narrative.
    Kept separate from execution so the LLM never drives tool order/parallelism."""
    global _summary_agent
    if _summary_agent is None:
        _summary_agent = Agent(
            model=_get_model(),
            deps_type=ScanContext,
            system_prompt=(
                "You are ArmorGuard, an autonomous security analyst. Given the results of a "
                "completed vulnerability scan, write a concise 2-4 sentence executive summary "
                "of the target's security posture. Be factual; do not invent findings."
            ),
        )
                
    return _summary_agent


async def _summarize(deps: ScanContext, results: dict) -> Optional[str]:
    digest = ", ".join(f"{name}: {count} finding(s)" for name, count in results.items())

    prompt = (
        f"Target: {deps.target_url} ({deps.scan_mode} scan). "
        f"Attack surface discovered: {len(deps.discovered_urls)} endpoint(s), "
        f"{len(deps.discovered_params)} with parameters. "
        f"Tool results — {digest}. Summarise the security posture."
    )
    
    # Run the agent with dependencies
    result = await _get_summary_agent().run(prompt, deps=deps)
    text = (result.output or "").strip()
    return text or None


async def run_scan(
    scan_id: str,
    target_url: str,
    scan_mode: str,
    selected_tools: list,
    broadcast,
) -> None:
    """Run the scan as a deterministic, governed pipeline.

    Tools execute sequentially in the mode's defined order (discovery before attack),
    each gated by ArmorIQ, so the crawler's output reliably reaches nuclei/sqlmap. The
    LLM is used only to summarise results afterwards — not to orchestrate tools — which
    keeps ordering deterministic and avoids parallel-tool-call resource conflicts.
    """
    await broadcast({"event": "scan_started", "data": {"scanId": scan_id}})

    tools = get_tools_for_mode(scan_mode, selected_tools)
    plan = build_armoriq_plan(tools, target_url, scan_mode)
    policy = build_armoriq_policy(tools, target_url)

    plan_capture = armoriq_client.capture_plan(
        llm=LLM_PROVIDER,
        prompt=f"Perform a {scan_mode} security scan of {target_url}",
        plan=plan,
    )
    # Validity must comfortably exceed worst-case total scan runtime so the token can't
    # expire mid-scan and surface a benign timeout as a false intent-drift halt.
    intent_token = armoriq_client.get_intent_token(
        plan_capture, policy=policy, validity_seconds=900.0,
    )

    deps = ScanContext(
        scan_id=scan_id,
        target_url=target_url,
        scan_mode=scan_mode,
        selected_tools=tools,
        broadcast=broadcast,
        intent_token=intent_token,
    )

    results: dict = {}
    try:
        for name in tools:
            scanner = SCANNERS.get(name)
            if scanner is None:
                continue
            try:
                results[name] = await _run_scanner(scanner, deps)
            except AgentHaltedException:
                return  # intent_drift_detected + agent_halted already broadcast
            except Exception as e:
                # One tool failing must not abort the whole scan.
                await broadcast({"event": "tool_status", "data": {
                    "tool": name, "status": "done", "message": f"{name} error: {e}",
                }})
                results[name] = 0

        try:
            summary = await _summarize(deps, results)
            if summary:
                await broadcast({"event": "agent_reasoning", "data": {"text": summary}})
        except AgentHaltedException:
            # [ArmorGuard AI Rewrite] - If ArmorIQ halts during the summary phase due to 
            # prompt injection, abort immediately and DO NOT broadcast scan_completed.
            return
        except Exception as e:
            print(f"SUMMARIZE FAILED WITH EXCEPTION: {e}", flush=True)
            traceback.print_exc()

        # Mark the plan completed in the ArmorIQ dashboard (no-op in mock mode).
        # Only reached when the scan ran to completion — a halted scan returns early.
        await asyncio.to_thread(governance.complete, intent_token.plan_id)
        await broadcast({"event": "scan_completed", "data": {"scanId": scan_id}})
    except Exception as e:
        await broadcast({"event": "scan_failed", "data": {"reason": str(e)}})
