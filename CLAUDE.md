# CLAUDE.md — ArmorGuard

## Owner Context

**Sujat is the sole owner of this entire repository.** There are no ownership
boundaries, per-folder splits, or teammate sign-offs. Edit any file in any folder
(`frontend/`, `agent/`, `demo-target/`, `backend/`, `scripts/`, `docs/`) freely. No
change requires "team approval" — Sujat's direction is the only authority.

## Coding Conventions

- Python files & functions: `snake_case`; classes: `PascalCase`
- All JSON over the wire: `camelCase` (enforced by `CamelModel` in `backend/main.py`)
- Error responses: always `{ "error": "<code>", "message": "<human text>" }`
- Severity enum values: `Critical | High | Medium | Low` exactly — no free-text
- Log levels: `INFO` lifecycle, `WARNING` recoverable tool failure, `ERROR` unrecoverable

## Git Workflow

- Commit format: `feat(...): ...` / `fix(...): ...` / `docs(...): ...`
- Never add Co-Authored-By or any AI attribution to commit messages
- Branch + PR for substantial work; never force-push `main`

---

# Build Plan: Close the ArmorIQ Integration Gaps

## Why

A judge from ArmorIQ rated the project 7/10 and said it "didn't do anything with
ArmorIQ" and suggested an agent+agent architecture. The installed SDK
(`backend/venv/Lib/site-packages/armoriq_sdk/`) confirms the critique:

- The agent gates tools with **`client.verify_token()` only** — the SDK documents this as
  *"Local-only token validation (expiry + required-field checks)"* (`client.py:1052`).
  The real enforcement surface was never used:
  - `get_intent_token(policy=...)` — server-side policy validation (`policy_validation`/`policy_snapshot`)
  - `ArmorIQSession.check()` / `enforce_sdk()` → `POST /iap/sdk/enforce` — real allow/block/hold (`session.py:267`)
  - `session.report()` → `POST /iap/audit` — dashboard audit log (`session.py:431`)
  - `complete_plan()` / `update_plan_status()` — marks plans done in the dashboard (`client.py:1252`)
  - `delegate()` — CSRG token delegation to sub-agents (`client.py:959`)
  - `bootstrap()` — resolves/attributes the agent identity (`client.py:303`)
- `ARMORIQ_AGENT_ID` is empty in `backend/.env`; no policy was ever defined.
- Drift events are persisted to `intent_drift_events` but never **replayed** and have **no
  UI** — a halted scan shows only a generic red "failed" badge. The frontend WS handler
  (`useGetScanLogs`, `api.ts:216`) ignores `intent_drift_detected` and `agent_halted`.

Goal: make ArmorIQ a first-class, dashboard-visible governance layer (real policy
enforcement, audit, plan completion, named agent), rebuild the pipeline into an
orchestrator + governed sub-agents (delegation), and give intent-drift incidents a proper
UI. Keep the existing API stable — new behavior rides the existing `intent_drift_detected`
WS event; no new routes.

## Manual ArmorIQ dashboard steps (Sujat does these in platform.armoriq.ai)

1. **Create/locate the agent** → copy its Agent ID into `backend/.env` (`ARMORIQ_AGENT_ID=`).
2. **Create a Policy** scoped to this agent: `allowedTools` = the 9 scanner names
   (`nmap, katana, ffuf, arjun, httpx, nuclei, nikto, sqlmap, hydra`), target scope =
   approved target, `defaultEnforcementAction = block`.

All code degrades gracefully if these aren't done yet (deterministic local backstop stays
in place); the dashboard "wow" appears once they are.

## Workstream A — Agent registration + bootstrap ✅ DONE

**Files:** `backend/.env`, `agent/governance/armoriq_client.py`

- ✅ `ARMORIQ_AGENT_ID` wired from `backend/.env` via `agent/config.py`
- ✅ `client.bootstrap()` called after construction in try/except; logs `agent=`, `org=`, `mcps=`, `toolMap=` at INFO; never fails init on error (`armoriq_client.py:197–210`)
- ✅ `bootstrap()` no-op added to `MockArmorIQClient` with correct return shape (`armoriq_client.py:34–43`)

## Workstream B — Real ArmorIQ enforcement (core) ✅ DONE

**Files:** `agent/governance/policies.py`, `agent/governance/armoriq_client.py`, `agent/agent.py`

1. ✅ `build_armoriq_policy(tools, target_url)` in `policies.py` (allowedTools + targetScope + defaultEnforcementAction=block); passed into `get_intent_token(plan_capture, policy=policy, validity_seconds=900)` in `run_scan` (`agent.py:379–390`)
2. ✅ **Governance facade** `Governance` class in `armoriq_client.py` (`armoriq_client.py:218–308`):
   - `governance.enforce(token, action, target, params) -> EnforceResult` — real path uses `ArmorIQSession(mode="sdk")` `.check()`; mock applies deterministic keyword logic
   - `governance.report_tool(token, action, params, result, status)` — real → `session.report()`; mock no-op
   - `governance.complete(plan_id)` — real → `client.complete_plan()`; mock no-op
3. ✅ `_armoriq_gate` (`agent.py:107`) calls `governance.enforce()`; three-layer check: token expiry → deterministic scope backstop → server-side enforce; `block`/`hold` → `PolicyBlockedException` → `_handle_armoriq_block` emits `intent_drift_detected`
4. ✅ `governance.report_tool(...)` called after each scanner in `_run_scanner` (`agent.py:273–276`)
5. ✅ `governance.complete(intent_token.plan_id)` called at end of `run_scan` (`agent.py:432`), only on successful completion — halted scans return early
6. ✅ `MockArmorIQClient` extended with `bootstrap`, `complete_plan`, `update_plan_status` no-ops

## Workstream C — Incident panel UI ✅ DONE

**Files:** `backend/database.py`, `backend/main.py`,
`frontend/lib/api-client-react/src/generated/api.ts`, `frontend/src/pages/scan-detail.tsx`

- ✅ **Backend:** `get_intent_drift_event(scan_id)` added to `database.py`. In
  `_replay_snapshot` (`main.py`), if a drift row exists, emit `intent_drift_detected`
  so reconnect re-shows the incident.
- ✅ **Frontend hook:** `useGetScanLogs` handles `intent_drift_detected` — pushes a
  `[POLICY BLOCK]` terminal line with classification, attempted action, and block reason.
  Incident is surfaced in the live terminal; a separate card is not needed.
- ✅ **StatusBadge:** `halted` state added to `scan-detail.tsx` distinct from generic "failed".

## Workstream D — Agent+agent delegation (full refactor) ⬜ TODO

**Files:** `agent/agent.py` (primary), `agent/governance/armoriq_client.py`,
`agent/governance/policies.py`

Restructure `run_scan` into an **orchestrator + 3 governed sub-agents**:

- **Orchestrator** mints the root intent token (full plan), then per sub-agent obtains a
  **scoped delegated token** via `governance.delegate(root_token, allowed_actions=phase_tools,
  target_agent=<name>, subtask={...})` (real → `client.delegate()`; mock → synthesize a
  delegated `IntentToken` restricted to `allowed_actions`).
- **Sub-agents** (deterministic, ordered — no LLM tool orchestration):
  - `recon` → nmap, katana, ffuf, arjun (writes `discovered_urls` / `discovered_params`)
  - `exploit` → httpx, nuclei, nikto, sqlmap, hydra (reads recon output)
  - `report` → existing summary agent (where the prompt-injection drift fires)
- Each sub-agent gates every tool against **its own delegated token**, reports via
  `governance.report_tool`, returns findings to the orchestrator. ScanContext is threaded
  recon→exploit→report to preserve discovery→attack data flow.
- **Fallback** if `/delegation/create` isn't enabled: mint a per-sub-agent scoped token via
  `get_intent_token` with a sub-plan (still demonstrates scoped governance; logs fallback).
- **API safety:** reuse existing `tool_status` / `agent_reasoning` event shapes; convey
  sub-agent boundaries via an optional `subAgent` key inside `tool_status.data` + an
  `agent_reasoning` line per phase. No new WS event types, no REST changes.

## UI Polish & PDF ✅ DONE (not in original plan — completed in sujat/ui-polish-and-pdf)

- ✅ Session sidebar: live status dots (running / queued / completed / failed)
- ✅ Dashboard: toast notification when a background scan fails or completes
- ✅ Recent Activity: status-aware messages (not always "Scan completed")
- ✅ Findings tab: single scrollable panel; risk score + sev pills in title bar; "Copy all" button
- ✅ Fix-prompt: consistent theme styling (`bg-accent` header / `bg-muted` body)
- ✅ PDF: Security Policy Incident section (classification, attempted action, block reason, error code)
- ✅ PDF: filename derived from target hostname (`armorguard-demo-target.pdf`)
- ✅ PDF: URLs defanged with `[://]` notation; snake_case values humanized to Title Case
- ✅ PDF: branded dark header with accent line; dynamic risk score color; cleaned-up layout
- ✅ PDF: download available for failed scans that have findings (not gated on completed only)

## Critical files

| File | Change | Status |
|---|---|---|
| `backend/.env` | set `ARMORIQ_AGENT_ID` | ✅ |
| `agent/governance/armoriq_client.py` | bootstrap on init; governance facade (enforce/report/complete); extend mock | ✅ |
| `agent/governance/policies.py` | `build_armoriq_policy()`; phase→tools grouping for Workstream D | ✅ |
| `agent/agent.py` | real enforcement gate + report_tool + complete_plan | ✅ |
| `agent/agent.py` | orchestrator + 3 sub-agents w/ delegated tokens (Workstream D) | ⬜ |
| `backend/database.py` | `get_intent_drift_event()` | ✅ |
| `backend/main.py` | replay drift event in `_replay_snapshot` | ✅ |
| `frontend/lib/api-client-react/src/generated/api.ts` | handle `intent_drift_detected` in WS; push `[POLICY BLOCK]` terminal line | ✅ |
| `frontend/src/pages/scan-detail.tsx` | `halted` status badge; incident shown in terminal | ✅ |
| `backend/pdf_export.py` | incident section, humanized values, defanged URLs, new design | ✅ |

## Verification (end-to-end)

1. `docker compose up --build`; backend logs show `[ArmorIQ] bootstrap: agent=<id> …` (not mock fallback).
2. Default scan on `http://demo-target:5000`. ArmorIQ dashboard shows: plan attributed to
   the named agent, delegations to recon/exploit/report sub-agents, an audit-log entry per
   tool, and the plan flipping to **completed**.
3. Prompt-injection path: enforcement returns **block**, `intent_drift_detected` streams,
   incident card renders with `prompt_injection` + matched policy, badge reads **halted**.
4. Refresh scan-detail post-incident → `_replay_snapshot` re-emits the drift event → card persists.
5. Policy not yet configured → scan still completes and off-scope block still fires (local backstop).
6. `ARMORIQ_MOCK=true` → scan boots and completes; facade no-ops don't crash; synthesized delegated tokens scope correctly.

## Notes

- No new REST routes or response-shape changes; new code rides existing WS events and adds
  only optional fields inside existing event `data`.
- `requirements.txt` unchanged (armoriq-sdk already present).
- Tools are baked into the backend image at `/opt/tools` (PATH precedence over the Python
  `httpx` CLI). nikto from source; ffuf wordlist at `scripts/wordlists/common.txt`.
- LLM: Groq `llama-3.3-70b-versatile`. Use `host.docker.internal` to reach host services
  from inside containers.
