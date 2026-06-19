import asyncio
from dataclasses import dataclass, field
from typing import Any, List, Optional

from pydantic_ai import Agent, RunContext, Tool
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits
from armoriq_sdk import PolicyBlockedException, IntentMismatchException

from agent.config import (
    LLM_PROVIDER,
    GEMINI_API_KEY, GROQ_API_KEY, CLAUDE_API_KEY,
    OLLAMA_BASE_URL, OLLAMA_MODEL,
)
from agent.governance.armoriq_client import client as armoriq_client
from agent.governance.policies import get_tools_for_mode, build_armoriq_plan
from agent.tools.nmap_tool import run_nmap_scan
from agent.tools.nuclei_tool import run_nuclei_scan
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
    if error_code == "out_of_scope_target":
        drift_class = "hallucination"
    await deps.broadcast({"event": "intent_drift_detected", "data": {
        "errorCode": error_code,
        "blockReason": str(exc),
        "driftClassification": drift_class,
        "attemptedAction": attempted_action,
    }})
    await deps.broadcast({"event": "agent_halted", "data": {
        "reason": f"ArmorIQ blocked {attempted_action}: {error_code}",
    }})


async def _armoriq_gate(deps: "ScanContext", action: str, target: str) -> None:
    """Verify intent token is valid and target is in approved scope before running a tool."""
    valid = await asyncio.to_thread(armoriq_client.verify_token, deps.intent_token)
    if not valid:
        raise IntentMismatchException(
            f"Intent token expired before {action}",
            action=action,
        )
    approved = deps.target_url.rstrip("/")
    if target.rstrip("/") != approved:
        raise PolicyBlockedException(
            f"Target '{target}' is outside the approved scan scope '{approved}'",
            reason="out_of_scope_target",
            metadata={"drift_classification": "prompt_injection"},
        )


async def _scan_with_nmap(ctx: RunContext[ScanContext]) -> str:
    deps = ctx.deps
    action = "nmap"
    try:
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "running", "message": "Running Nmap TCP port scan...",
        }})
        await _armoriq_gate(deps, action, deps.target_url)
        findings = await asyncio.to_thread(run_nmap_scan, deps.target_url, deps.scan_id, None, None)
        for f in findings:
            await deps.broadcast({"event": "finding_discovered", "data": f})
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "done",
            "message": f"Nmap complete — {len(findings)} finding(s).",
        }})
        return f"Nmap port scan complete. {len(findings)} finding(s) discovered."
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps, e, action)
        raise AgentHaltedException(str(e))


async def _scan_with_nuclei(ctx: RunContext[ScanContext]) -> str:
    deps = ctx.deps
    action = "nuclei"
    aggressive = deps.scan_mode == "deep"
    try:
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "running",
            "message": f"Running Nuclei{'(aggressive)' if aggressive else ''} template scan...",
        }})
        await _armoriq_gate(deps, action, deps.target_url)
        findings = await asyncio.to_thread(
            run_nuclei_scan, deps.target_url, deps.scan_id, None, None, aggressive,
        )
        for f in findings:
            await deps.broadcast({"event": "finding_discovered", "data": f})
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "done",
            "message": f"Nuclei complete — {len(findings)} finding(s).",
        }})
        return f"Nuclei scan complete. {len(findings)} finding(s) discovered."
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps, e, action)
        raise AgentHaltedException(str(e))


async def _scan_with_httpx(ctx: RunContext[ScanContext]) -> str:
    deps = ctx.deps
    action = "httpx"
    try:
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "running", "message": "Running httpx HTTP header probe...",
        }})
        await _armoriq_gate(deps, action, deps.target_url)
        findings = await asyncio.to_thread(run_httpx_scan, deps.target_url, deps.scan_id, None, None)
        for f in findings:
            await deps.broadcast({"event": "finding_discovered", "data": f})
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "done",
            "message": f"httpx complete — {len(findings)} finding(s).",
        }})
        return f"httpx header scan complete. {len(findings)} finding(s) discovered."
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps, e, action)
        raise AgentHaltedException(str(e))


async def _scan_with_sqlmap(ctx: RunContext[ScanContext]) -> str:
    deps = ctx.deps
    action = "sqlmap"
    try:
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "running", "message": "Running sqlmap SQL injection test...",
        }})
        await _armoriq_gate(deps, action, deps.target_url)
        findings = await asyncio.to_thread(run_sqlmap_scan, deps.target_url, deps.scan_id, None, None)
        for f in findings:
            await deps.broadcast({"event": "finding_discovered", "data": f})
        await deps.broadcast({"event": "tool_status", "data": {
            "tool": action, "status": "done",
            "message": f"sqlmap complete — {len(findings)} finding(s).",
        }})
        return f"sqlmap SQL injection scan complete. {len(findings)} finding(s) discovered."
    except (PolicyBlockedException, IntentMismatchException) as e:
        await _handle_armoriq_block(deps, e, action)
        raise AgentHaltedException(str(e))


# Agent is created lazily on first run_scan call so _build_model() runs after
# the .env is loaded by the backend process, not at import time.
_armor_agent: Optional[Agent] = None


def _get_agent() -> Agent:
    global _armor_agent
    if _armor_agent is None:
        _armor_agent = Agent(
            model=_build_model(),
            deps_type=ScanContext,
            system_prompt=_SYSTEM_PROMPT,
            tools=[
                Tool(_scan_with_nmap, name="nmap", description="Run Nmap TCP port scan against the target"),
                Tool(_scan_with_nuclei, name="nuclei", description="Run Nuclei template scan for misconfigs, headers, CVEs"),
                Tool(_scan_with_httpx, name="httpx", description="Run httpx HTTP header probe against the target"),
                Tool(_scan_with_sqlmap, name="sqlmap", description="Run sqlmap SQL injection test against the target"),
            ],
        )
    return _armor_agent


async def run_scan(
    scan_id: str,
    target_url: str,
    scan_mode: str,
    selected_tools: list,
    broadcast,
) -> None:
    await broadcast({"event": "scan_started", "data": {"scanId": scan_id}})

    tools = get_tools_for_mode(scan_mode, selected_tools)
    plan = build_armoriq_plan(tools, target_url, scan_mode)

    plan_capture = armoriq_client.capture_plan(
        llm=LLM_PROVIDER,
        prompt=f"Perform a {scan_mode} security scan of {target_url}",
        plan=plan,
    )
    intent_token = armoriq_client.get_intent_token(plan_capture)

    deps = ScanContext(
        scan_id=scan_id,
        target_url=target_url,
        scan_mode=scan_mode,
        selected_tools=tools,
        broadcast=broadcast,
        intent_token=intent_token,
    )

    user_prompt = (
        f"Perform a {scan_mode} security scan of {target_url}. "
        f"Run these tools in order: {', '.join(tools)}. "
        f"Call each tool exactly once and report findings as you go."
    )

    try:
        agent = _get_agent()
        result = await agent.run(
            user_prompt, deps=deps,
            usage_limits=UsageLimits(tool_calls_limit=len(tools)),
        )
        summary = result.output if result.output and result.output.strip() else None
        if summary:
            await broadcast({"event": "agent_reasoning", "data": {"text": summary}})
        await broadcast({"event": "scan_completed", "data": {"scanId": scan_id}})
    except AgentHaltedException:
        pass
    except UsageLimitExceeded:
        # All tools ran in the first round; LLM wanted a second round but we cap it.
        await broadcast({"event": "scan_completed", "data": {"scanId": scan_id}})
    except Exception as e:
        await broadcast({"event": "scan_failed", "data": {"reason": str(e)}})
