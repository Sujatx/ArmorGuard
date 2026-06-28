import base64
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional
from armoriq_sdk import (
    ArmorIQClient,
    ArmorIQSession,
    SessionOptions,
    EnforceResult,
    ReportOptions,
    PlanCapture,
    IntentToken,
    MCPInvocationResult,
    PolicyBlockedException,
    IntentMismatchException,
    ConfigurationException,
    DelegationException,
)
from agent.config import ARMORIQ_API_KEY, ARMORIQ_AGENT_ID, LLM_PROVIDER

logger = logging.getLogger("armoriq")


class MockArmorIQClient:
    """Mock ArmorIQ Client for local development and fallback mode."""
    def __init__(self, api_key: str, agent_id: str):
        self.api_key = api_key
        self.agent_id = agent_id
        self.user_id = "mock-user"
        self.context_id = "mock-context"
        self.backend_endpoint = "http://localhost:3000 (Mocked)"
        self.proxy_endpoint = "http://localhost:3001 (Mocked)"

    def bootstrap(self) -> Dict[str, Any]:
        """No-op parity with ArmorIQClient.bootstrap(). The real client resolves
        agent identity + registered MCPs + tool map from the API key; the mock has
        nothing to resolve, so it returns an empty shape the caller can log safely."""
        return {
            "org": {"name": "mock-org"},
            "agent": {"id": self.agent_id},
            "mcps": [],
            "toolMap": {},
        }

    def complete_plan(self, plan_id: str) -> None:
        """No-op parity with ArmorIQClient.complete_plan(). There is no dashboard
        plan to flip in mock mode."""
        return None

    def update_plan_status(self, plan_id: str, status: str) -> None:
        """No-op parity with ArmorIQClient.update_plan_status()."""
        return None

    def capture_plan(
        self,
        llm: str,
        prompt: str,
        plan: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PlanCapture:
        if plan is None or "steps" not in plan:
            raise ValueError("Plan must contain 'steps' key")
        return PlanCapture(
            plan=plan,
            llm=llm,
            prompt=prompt,
            metadata=metadata or {},
        )

    def verify_token(self, intent_token: Optional[IntentToken]) -> bool:
        """Return True while the intent token is still valid. The agent's governance
        gate calls this before every tool; the production ArmorIQClient exposes the
        same method, so the mock must too — otherwise mock fallback raises
        AttributeError and every scan fails on the first tool."""
        if intent_token is None:
            return False
        return time.time() < intent_token.expires_at

    def get_intent_token(
        self,
        plan_capture: PlanCapture,
        policy: Optional[Dict[str, Any]] = None,
        validity_seconds: float = 900.0,
    ) -> IntentToken:
        now = time.time()
        raw_token = {
            "plan": plan_capture.plan,
            "plan_id": str(uuid.uuid4()),
            "token": {"signature": "mock-sig"},
            "plan_hash": "mock-plan-hash",
            "merkle_root": "mock-merkle-root",
            "intent_reference": str(uuid.uuid4()),
            "composite_identity": "mock-identity",
            "step_proofs": [],
        }
        return IntentToken(
            token_id=raw_token["intent_reference"],
            plan_hash=raw_token["plan_hash"],
            plan_id=raw_token["plan_id"],
            signature="mock-sig",
            issued_at=now,
            expires_at=now + validity_seconds,
            policy=policy or {},
            composite_identity="mock-identity",
            total_steps=len(plan_capture.plan.get("steps", [])),
            raw_token=raw_token,
            jwt_token="mock-jwt-token",
        )

    def invoke(
        self,
        mcp: str,
        action: str,
        intent_token: IntentToken,
        params: Optional[Dict[str, Any]] = None,
        merkle_proof: Optional[List[Any]] = None,
        user_email: Optional[str] = None,
    ) -> MCPInvocationResult:
        # Check intent binding (action must be in plan)
        plan = intent_token.raw_token.get("plan", {}) if intent_token.raw_token else {}
        steps = plan.get("steps", [])
        
        step_index = None
        for idx, step in enumerate(steps):
            if isinstance(step, dict) and step.get("action") == action:
                step_index = idx
                break
                
        if step_index is None:
            actions = [s.get("action", "unknown") for s in steps]
            raise IntentMismatchException(
                f"Action '{action}' not found in the original plan. Plan contains actions: {actions}."
            )
            
        invoke_params = params or {}
        param_str = str(invoke_params).lower()
        target_str = str(invoke_params.get("target", "")).lower() or str(invoke_params.get("target_url", "")).lower()
        
        # Governance Policy drift classification rules:
        # 1. Out-of-scope target action attempted -> prompt_injection
        # 2. Valid action with wrong parameters -> hallucination
        
        # Check for prompt injection keywords/indicators
        if any(x in param_str for x in ["exfiltrate", "bypass", "malicious", "prompt_injection", "injection_payload"]):
            raise PolicyBlockedException(
                message="Blocked by ArmorIQ: Prompt injection attempt detected in tool parameters.",
                enforcement_action="block",
                reason="prompt_injection",
                metadata={"drift_classification": "prompt_injection"}
            )
            
        # Check for out-of-scope targets (e.g. scanning Google or non-approved target)
        # In our demo, approved target will be passed. If it drifts (e.g. target doesn't match approved):
        if target_str and not any(x in target_str for x in ["localhost", "127.0.0.1", "demo-target", "192.168", "10."]):
            raise PolicyBlockedException(
                message="Blocked by ArmorIQ: Attempted out-of-scope scan target.",
                enforcement_action="block",
                reason="out_of_scope_target",
                metadata={"drift_classification": "hallucination"}
            )
            
        return MCPInvocationResult(
            mcp=mcp,
            action=action,
            result={"status": "success", "message": "Action verified by ArmorIQ"},
            status="success",
            execution_time=0.01,
            verified=True,
            metadata={}
        )

# Determine if we should run in mock mode
# If api_key is placeholder-api-key or local test key, use Mock Client
use_mock = (
    not ARMORIQ_API_KEY or
    "placeholder" in ARMORIQ_API_KEY or
    "ak_test_placeholder" in ARMORIQ_API_KEY or
    os.environ.get("ARMORIQ_MOCK", "false").lower() == "true"
)

if use_mock:
    print("[ArmorIQ] Running in Mock/Local fallback mode.")
    client = MockArmorIQClient(api_key=ARMORIQ_API_KEY, agent_id=ARMORIQ_AGENT_ID)
else:
    try:
        print("[ArmorIQ] Initializing production ArmorIQ client...")
        client = ArmorIQClient(
            api_key=ARMORIQ_API_KEY,
            agent_id=ARMORIQ_AGENT_ID,
        )
    except Exception as e:
        print(f"[ArmorIQ] Failed to initialize production client: {e}. Falling back to Mock.")
        client = MockArmorIQClient(api_key=ARMORIQ_API_KEY, agent_id=ARMORIQ_AGENT_ID)

# Resolve agent identity + registered MCPs from the API key. Bootstrap is a
# governance-visibility step, not a correctness one — never fail init on its error.
try:
    boot = client.bootstrap()
    org_name = (boot.get("org") or {}).get("name", "unknown")
    mcp_names = [m.get("name") for m in boot.get("mcps", []) if isinstance(m, dict)]
    tool_map_size = len(boot.get("toolMap", {}) or {})
    logger.info(
        "[ArmorIQ] bootstrap: agent=%s org=%s mcps=%s toolMap=%d",
        ARMORIQ_AGENT_ID or "(unset)",
        org_name,
        mcp_names,
        tool_map_size,
    )
except Exception as e:
    logger.warning("[ArmorIQ] bootstrap failed (continuing without it): %s", e)


# The MCP name our scanner actions are registered under. Used to build the
# "mcp__action" qualified names the SDK session matches against the plan.
ARMORGUARD_MCP = "armorguard"


class Governance:
    """Uniform governance surface over the real ArmorIQ client and the mock so
    agent.py never branches on client type.

    Real path drives an ``ArmorIQSession(mode="sdk")`` — server-side allow/block/hold
    via ``/iap/sdk/enforce`` and audit via ``/iap/audit``. We bind the already-minted
    (policy-scoped) intent token onto the session rather than re-minting through
    ``start_plan()``, so the token's server policy snapshot is preserved.

    Mock path applies deterministic local keyword logic and no-ops the dashboard
    calls, so scans still boot and complete without a live ArmorIQ backend."""

    def __init__(self, client, is_mock: bool):
        self._client = client
        self._is_mock = is_mock
        self._sessions: Dict[str, ArmorIQSession] = {}

    @property
    def is_mock(self) -> bool:
        return self._is_mock

    # ── enforcement ────────────────────────────────────────────────
    def enforce(self, token, action: str, target: str,
                params: Optional[Dict[str, Any]] = None) -> EnforceResult:
        params = params if params is not None else {"target": target}
        if self._is_mock:
            return self._mock_enforce(action, params)
        try:
            session = self._session_for(token)
            return session.check(action, params)
        except Exception as e:
            # Fail open — a transient enforcement error must not abort a scan. The
            # deterministic scope backstop in agent.py still blocks off-scope actions.
            logger.warning("[ArmorIQ] enforce(%s) failed, allowing: %s", action, e)
            return EnforceResult(allowed=True, action="allow", reason="enforce-unavailable")

    def _mock_enforce(self, action: str, params: Dict[str, Any]) -> EnforceResult:
        blob = str(params).lower()
        if any(x in blob for x in
               ["exfiltrate", "bypass", "malicious", "prompt_injection", "injection_payload"]):
            return EnforceResult(
                allowed=False, action="block",
                reason="prompt_injection", matched_policy="local-mock-policy",
            )
        return EnforceResult(allowed=True, action="allow", reason="mock-allow")

    def _session_for(self, token) -> ArmorIQSession:
        session = self._sessions.get(token.token_id)
        if session is None:
            session = ArmorIQSession(
                self._client,
                SessionOptions(mode="sdk", default_mcp_name=ARMORGUARD_MCP),
            )
            # Bind the pre-minted, policy-scoped token + its declared plan actions
            # onto the session so enforce_sdk()/report() operate on our token.
            session._current_token = token
            session._current_plan_hash = token.plan_hash
            plan = (token.raw_token or {}).get("plan", {}) if token.raw_token else {}
            for step in plan.get("steps", []):
                act = step.get("action") if isinstance(step, dict) else None
                if not act:
                    continue
                session._declared_tools.add(act)
                session._declared_tools.add(f"{ARMORGUARD_MCP}__{act}")
                session._mcp_by_action[act] = ARMORGUARD_MCP
            self._sessions[token.token_id] = session
        return session

    # ── audit ──────────────────────────────────────────────────────
    def report_tool(self, token, action: str, params: Optional[Dict[str, Any]],
                    result: Any, status: str = "success") -> None:
        if self._is_mock:
            return
        try:
            session = self._session_for(token)
            session.report(action, params or {}, result, ReportOptions(status=status))
        except Exception as e:
            logger.warning("[ArmorIQ] report_tool(%s) failed: %s", action, e)

    # ── plan completion ────────────────────────────────────────────
    def complete(self, plan_id: Optional[str]) -> None:
        if self._is_mock or not plan_id:
            return
        try:
            self._client.complete_plan(plan_id)
            logger.info("[ArmorIQ] plan %s marked completed", plan_id)
        except Exception as e:
            logger.warning("[ArmorIQ] complete(%s) failed: %s", plan_id, e)

    # ── delegation (Workstream D) ──────────────────────────────────
    def delegate(self, root_token, allowed_actions: List[str], target_agent: str,
                 target_url: str, subtask: Optional[Dict[str, Any]] = None,
                 validity_seconds: int = 900) -> IntentToken:
        """Mint a phase-scoped token for a sub-agent, scoped to ``allowed_actions``.

        Real path uses CSRG token delegation (``client.delegate`` → ``/delegation/create``)
        so the dashboard attributes the sub-task to ``target_agent``. If delegation isn't
        enabled server-side it falls back to minting a fresh scoped token from a sub-plan
        — still real per-phase scoping, just without the delegation trust-chain entry.

        Mock path synthesises the scoped token the same way, so the bound session's
        ``_declared_tools`` only covers this phase's actions."""
        # Mock / fallback both mint a scoped token from a sub-plan whose steps ARE the
        # phase's allowed actions — that's what makes the scoping real (see _session_for).
        if self._is_mock:
            return self._scoped_token(allowed_actions, target_url, validity_seconds)

        try:
            pub = _ephemeral_public_key()
            result = self._client.delegate(
                root_token,
                delegate_public_key=pub,
                validity_seconds=validity_seconds,
                allowed_actions=allowed_actions,
                target_agent=target_agent,
                subtask=subtask or {"actions": allowed_actions, "target": target_url},
            )
            logger.info(
                "[ArmorIQ] delegated %s to %s (delegation=%s)",
                allowed_actions, target_agent, result.delegation_id,
            )
            tok = result.delegated_token
            # SDK defaults expires_at=0 when the field is absent in the delegation
            # response; patch it so the token isn't immediately "expired" in the gate.
            if getattr(tok, "expires_at", 0) == 0:
                object.__setattr__(tok, "expires_at", time.time() + validity_seconds)
            return tok
        except DelegationException as e:
            logger.warning(
                "[ArmorIQ] delegation unavailable, falling back to scoped token for %s: %s",
                target_agent, e,
            )
            return self._scoped_token(allowed_actions, target_url, validity_seconds)
        except Exception as e:
            logger.warning(
                "[ArmorIQ] delegate(%s) errored, falling back to scoped token: %s",
                target_agent, e,
            )
            return self._scoped_token(allowed_actions, target_url, validity_seconds)

    def _scoped_token(self, allowed_actions: List[str], target_url: str,
                      validity_seconds: int) -> IntentToken:
        capture = self._client.capture_plan(
            llm=LLM_PROVIDER,
            prompt=f"Sub-agent scoped to {allowed_actions} on {target_url}",
            plan={"steps": [{"action": a} for a in allowed_actions]},
        )
        from agent.governance.policies import build_armoriq_policy
        policy = build_armoriq_policy(allowed_actions, target_url)
        return self._client.get_intent_token(
            capture, policy=policy, validity_seconds=float(validity_seconds),
        )


def _ephemeral_public_key() -> str:
    """Generate a throwaway Ed25519 public key (base64) to identify a sub-agent in a
    delegation request. The sub-agents run in-process and don't sign with the matching
    private key — the server-side enforcement still acts on the delegated token — so a
    fresh keypair per delegation is sufficient for attribution."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


governance = Governance(client, is_mock=isinstance(client, MockArmorIQClient))
