import os
import time
import uuid
from typing import Any, Dict, List, Optional
from armoriq_sdk import (
    ArmorIQClient,
    PlanCapture,
    IntentToken,
    MCPInvocationResult,
    PolicyBlockedException,
    IntentMismatchException,
    ConfigurationException,
)
from agent.config import ARMORIQ_API_KEY, ARMORIQ_AGENT_ID

class MockArmorIQClient:
    """Mock ArmorIQ Client for local development and fallback mode."""
    def __init__(self, api_key: str, agent_id: str):
        self.api_key = api_key
        self.agent_id = agent_id
        self.user_id = "mock-user"
        self.context_id = "mock-context"
        self.backend_endpoint = "http://localhost:3000 (Mocked)"
        self.proxy_endpoint = "http://localhost:3001 (Mocked)"

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
