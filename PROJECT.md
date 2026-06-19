# ArmorGuard — Master Project Document

**File:** PROJECT.md
**Purpose:** Single source of truth for project scope, architecture, contracts, conventions, ownership, and build progress. All teammates and AI coding assistants should treat this document as the authoritative context for the project.
**Audience:** All teammates and AI coding assistants.
**Status:** Draft
**Last Updated:** <!-- date — name -->

## Table of Contents

- [1. Overview](#1-overview)
- [2. Problem & Solution](#2-problem--solution)
- [3. Conventions](#3-conventions)
- [4. Tech Stack](#4-tech-stack)
- [5. Architecture](#5-architecture)
- [6. Data Models](#6-data-models)
- [7. Contracts](#7-contracts)
- [8. Folder Structure](#8-folder-structure)
- [9. Ownership & Build Plan](#9-ownership--build-plan)
- [10. Integration Checkpoints](#10-integration-checkpoints)
- [11. Fallback Plan](#11-fallback-plan)
- [12. Definition of Done & Demo Lock](#12-definition-of-done--demo-lock)
- [13. Change Control](#13-change-control)

---

## 1. Overview

**Project name:** ArmorGuard

**Hackathon / event:** NeuroX 2026 (HackBriven) — June 21st, CDS Campus, Masters' Union, Gurugram.

**Sponsor / partner:** ArmorIQ (must-use sponsor track — the ArmorIQ SDK is required).

**Description:** ArmorGuard is an autonomous AI pentesting agent built for vibe coders — people who ship AI-built applications without proper security audits. It actively probes a target for real vulnerabilities and generates a severity-scored forensic report automatically. Every tool call the agent makes is validated in real time by the ArmorIQ SDK — if a malicious page prompt-injects the agent mid-task, ArmorIQ detects the intent drift and halts execution immediately.

---

## 2. Problem & Solution

**Core problem being solved:**
- Vibe coders ship AI-built applications into production without any meaningful security review.
- Autonomous AI agents that are given tool access (the kind needed to pentest) can themselves be hijacked mid-task via prompt injection on a malicious target, with no real-time mechanism to detect or stop it.

**Target users:** Vibe coders and small teams who ship AI-generated applications quickly and have no existing security audit process.

**Existing gap:** Traditional pentesting tools require security expertise to operate and interpret. Autonomous AI agents that automate this process introduce a new risk surface — an agent can be prompt-injected by the very target it is testing, with no built-in way to detect that its intent has drifted from the operator's original instruction.

**Proposed solution:** An autonomous AI agent that runs real pentesting tools (Nmap, Nuclei, sqlmap, httpx) against a target, with every single tool call validated in real time by the ArmorIQ SDK before execution. If the agent's intent drifts from its authorized scope — whether from prompt injection or hallucination — ArmorIQ halts the agent immediately and surfaces the incident to the operator.

**Differentiators:**
- Two equal pillars in one system: autonomous AI-driven pentesting *and* defensive AI agent integrity governance — not just a scanner, but a scanner that polices its own agent's behavior.
- Real-time intent drift detection and halt, not a post-hoc log review.

---

## 3. Conventions

These rules apply across the entire codebase, regardless of who or what (human or AI) is writing the code, to prevent drift between components built by different people/sessions.

### Naming Conventions

**Frontend:**
- Components → `PascalCase` (e.g. `ScanTerminal.tsx`)
- Hooks → `camelCase` with `use` prefix (e.g. `useScanSocket.ts`)
- Utility files → `camelCase` (e.g. `formatSeverity.ts`)

**Backend:**
- Python files → `snake_case` (e.g. `scan_routes.py`)
- Functions → `snake_case` (e.g. `create_scan_record()`)
- Classes → `PascalCase` (e.g. `ScanRequest`)

**Database:**
- Tables → `snake_case`, plural (e.g. `findings`, `audit_log_events`)
- Columns → `snake_case` (e.g. `target_url`, `created_at`)

### Branch Naming

- `feature/frontend-dashboard`
- `feature/backend-scan-api`
- `feature/agent-tools`
- `fix/websocket-reconnect`

### Commit Format

- `feat(frontend): add live scan terminal`
- `feat(agent): implement nuclei tool`
- `fix(backend): validate consent record`
- `docs(project): update architecture`

### Standard Error Response

All APIs follow one consistent error shape:

```json
{
  "error": "string (machine-readable error code, e.g. consent_required)",
  "message": "string (human-readable description)"
}
```

This matches the `consent_required` error already defined in section 7 for `POST /scan`, and every other API error in the system must follow this same `error` + `message` shape.

### Logging Convention

| Level | Use For |
| --- | --- |
| `INFO` | Normal lifecycle events — scan started, tool started/finished, report generated |
| `WARNING` | Recoverable issues — a tool failed but the scan continues (see Fallback Plan, section 11) |
| `ERROR` | Unrecoverable failures — agent crash, Supabase write failure, scan marked `failed` |
| `SECURITY` | Any ArmorIQ block / intent drift event — always paired with an `IntentDriftEvent` row |

**Log ownership:** The backend service (owned by Sujat) owns log emission for all backend and agent code paths, since the agent runs inside the same FastAPI service.

**Storage location:** `INFO`/`WARNING`/`ERROR` logs go to stdout inside the backend container (captured by `docker compose logs`). `SECURITY` logs are additionally persisted as `AuditLogEvent` / `IntentDriftEvent` rows in Supabase so they survive container restarts and are queryable for the audit trail.

### AI Assistant Rules

AI assistants working on this codebase must:
- Not create new routes outside the documented contracts in section 7.
- Not modify contracts (section 7) without team approval.
- Not introduce new dependencies without approval.
- Not modify another owner's area (see section 9) without clearly flagging it.
- Not alter architecture, schemas, or ownership assignments without approval.
- Treat this document as the source of truth.

---

## 4. Tech Stack

| Component | Technology |
| --- | --- |
| Frontend | Next.js 14 (App Router) + Tailwind + shadcn/ui + Recharts + React Flow |
| Backend + Agent | FastAPI + PydanticAI (single Python service) |
| Governance | ArmorIQ SDK (manually wrapped around every PydanticAI tool call) |
| Real-time | Native FastAPI WebSockets |
| Database | Supabase (PostgreSQL) |
| Tools | Nmap (port scanning), Nuclei (admin panels, headers, misconfigs, error pages, CVEs), sqlmap (SQL injection), httpx (custom probes) |
| LLM Provider | Groq or Gemini (free tier) for build/testing phase → switch to Claude (Pro/API) for finals demo |
| Dev Start | Docker Compose — single `docker-compose up` boots frontend + backend containers |

**Unresolved (carried over from BUILDPLAN.md):** backend is currently assumed to need privileged mode for Nmap raw socket access — **NOT YET TESTED** whether non-privileged `-sT` (TCP connect scan) covers the planted vulnerabilities adequately. Test this before build day; if `-sT` is sufficient, drop privileged mode entirely.

---

## 5. Architecture

### High-Level Flow

```
User → Frontend → FastAPI → PydanticAI Agent → ArmorIQ → Tools → Findings → Supabase → Frontend
```

**Step by step:**
1. User enters target + selects scan mode (Default / Deep / Custom) on frontend.
2. Frontend detects target type — local skips consent, public triggers consent gate.
3. Consent acknowledged → `POST /consent` → FastAPI stores `ConsentRecord`.
4. `POST /scan` with target + scan mode + selected tools → FastAPI creates `Scan` record in Supabase.
5. FastAPI triggers the PydanticAI agent as a background task, opens a WebSocket to the frontend.
6. Agent runs tools based on scan mode — every tool call is wrapped with ArmorIQ `capture_plan` → `get_intent_token` → `invoke`.
7. LLM reasoning + tool call status streams via WebSocket → frontend terminal window updates live.
8. If ArmorIQ detects intent drift → agent halts, drift event streamed to frontend as an alert.
9. Agent finishes → FastAPI assembles the report, stores it in Supabase, sends the final assessment to the frontend.

**Scan Modes:**
- **Default** — Nmap + Nuclei + httpx (common vibe coder misconfigs).
- **Deep** — everything in Default + sqlmap + aggressive Nuclei templates.
- **Custom** — user selects individual tools from a checklist.

### Component Responsibilities

- **Frontend** — Next.js dashboard, scan controls (target input, mode selector, consent gate), live scan terminal/reasoning stream, and the report view (findings list, risk summary, vulnerability graph, PDF export trigger).
- **Backend** — FastAPI service exposing all REST and WebSocket contracts (section 7), persists `ConsentRecord`/`Scan`/`Finding`/`Report` data to Supabase, assembles reports, and generates PDF exports.
- **Agent** — PydanticAI agent running as a FastAPI background task; runs the registered tools (Nmap, Nuclei, sqlmap, httpx) according to scan mode, extracts findings from tool output, and streams reasoning + findings back through the WebSocket handler.
- **Governance Layer** — ArmorIQ SDK, initialized inside the same backend service. Wraps every agent tool call in `capture_plan` → `get_intent_token` → `invoke`; classifies and halts on intent drift (prompt injection or hallucination), emitting an `IntentDriftEvent`.
- **Database** — Supabase (PostgreSQL). Stores `ConsentRecord`, `Scan`, `Finding`, `AuditLogEvent`, and `IntentDriftEvent` rows. `Report` is computed at read time, not stored.
- **Demo Target** — A deliberately vulnerable third Docker container with planted vulnerabilities and an embedded prompt injection payload, used to exercise the full pentest + governance flow during the demo.

---

## 6. Data Models

These definitions are the single source of truth referenced by the contracts in section 7. No field should be redefined elsewhere.

### ConsentRecord

| Field | Type | Description |
| --- | --- | --- |
| `consentId` | string (UUID) | Unique identifier for the consent record |
| `targetUrl` | string | Target the operator is consenting to test |
| `operatorIp` | string | Operator IP, read server-side from the request — never trusted from client input |
| `timestamp` | string (ISO8601) | When consent was recorded |
| `acknowledged` | boolean | Whether the operator acknowledged the consent disclaimer |

### Scan

| Field | Type | Description |
| --- | --- | --- |
| `scanId` | string (UUID) | Unique identifier for the scan |
| `targetUrl` | string | Target being scanned |
| `scanMode` | enum: `default` \| `deep` \| `custom` | Selected scan mode |
| `selectedTools` | string[] | Tools selected by the user (only meaningful when `scanMode` is `custom`) |
| `status` | enum: `running` \| `completed` \| `failed` | Current scan status |
| `progress` | integer | Scan progress indicator |
| `consentId` | string (UUID) \| null | References the `ConsentRecord` that authorized this scan; `null` for local/private-IP targets |
| `createdAt` | string (ISO8601) | When the scan was created |

### Finding

| Field | Type | Description |
| --- | --- | --- |
| `findingId` | string (UUID) | Unique identifier for the finding |
| `scanId` | string (UUID) | The scan this finding belongs to |
| `severity` | enum: `Critical` \| `High` \| `Medium` \| `Low` | Fixed severity enum — no free-text values |
| `title` | string | Short finding title |
| `description` | string | What was found |
| `remediation` | string | How to fix it |
| `evidence` | string | Supporting evidence (raw tool output snippet, etc.) |
| `createdAt` | string (ISO8601) | When the finding was recorded |

### Report

| Field | Type | Description |
| --- | --- | --- |
| `scanId` | string (UUID) | The scan this report covers |
| `targetUrl` | string | Target that was scanned |
| `scanMode` | enum: `default` \| `deep` \| `custom` | Scan mode used |
| `summary.riskScore` | number | Computed risk score |
| `summary.totalFindings` | integer | Total number of findings |
| `summary.bySeverity` | object `{ Critical, High, Medium, Low }` (integers) | Count of findings per severity |
| `findings` | Finding[] | Findings list, using the `Finding` shape above |

> **Note:** `Report` has no dedicated database table. It is computed at read time by aggregating `scans` + `findings` — `riskScore` and `bySeverity` are derived via a `GROUP BY severity` query, not stored as columns.

### AuditLogEvent

| Field | Type | Description |
| --- | --- | --- |
| `id` | string (UUID) | Unique identifier for the event |
| `scanId` | string (UUID) | The scan this event belongs to |
| `eventType` | string | Type of audit event (e.g. tool call, scan lifecycle) |
| `message` | string | Human-readable event description |
| `metadata` | object (JSONB) | Arbitrary structured metadata for the event |
| `createdAt` | string (ISO8601) | When the event occurred |

### IntentDriftEvent

| Field | Type | Description |
| --- | --- | --- |
| `id` | string (UUID) | Unique identifier for the event |
| `scanId` | string (UUID) | The scan this event belongs to |
| `errorCode` | string | ArmorIQ error code for the block |
| `blockReason` | string | Why ArmorIQ blocked the action |
| `driftClassification` | enum: `prompt_injection` \| `hallucination` | Out-of-scope action = `prompt_injection`; valid action with wrong parameters = `hallucination` |
| `attemptedAction` | string | The action the agent attempted before being blocked |
| `createdAt` | string (ISO8601) | When the drift event occurred |

---

## 7. Contracts

These contracts are locked for the build. Any change requires flagging to the whole team before implementation, since frontend and backend will be built in parallel against these shapes. All request/response bodies reference the data models in section 6 rather than redefining fields inline.

### REST APIs

#### `POST /consent`

**Request:**
```json
{ "targetUrl": "string" }
```
- `operatorIp` is **not** sent by the client. The backend reads it server-side from the incoming request (`request.client.host` in FastAPI) so the audit trail can't be spoofed by a client lying in its own request body.

**Response:** `ConsentRecord` shape —
```json
{
  "consentId": "string",
  "targetUrl": "string",
  "operatorIp": "string",
  "timestamp": "ISO8601 string",
  "acknowledged": true
}
```

#### `POST /scan`

**Request:**
```json
{
  "targetUrl": "string",
  "scanMode": "default | deep | custom",
  "selectedTools": ["nmap", "nuclei", "sqlmap", "httpx"],
  "consentId": "string | null"
}
```

**Validation rules:**
- `scanMode` is optional — backend defaults to `default` if omitted.
- `selectedTools` is only required/used when `scanMode` is `custom`. If `custom` is selected and `selectedTools` is empty or missing, reject with `400` (`error: "tools_required"`).
- `consentId` is required if the target is public (backend validates it exists and `acknowledged: true`). Local/private-IP targets can omit it entirely.
- Backend **must** also verify that the `targetUrl` stored on the referenced `ConsentRecord` matches the `targetUrl` in this request — a `consentId` issued for one target must not authorize a scan against a different target. Mismatch → reject with the same `consent_required` error below.

**Response:**
```json
{ "scanId": "string", "status": "started" }
```

**Error response** (public target, missing or invalid consent):
```json
{ "error": "consent_required", "message": "string" }
```

#### `GET /scan/{scanId}`

Single source of truth for scan state — used for initial load, page refresh/resume, and as the WebSocket fallback (polling). Findings are included inline rather than split into a separate endpoint, so this one response works for both the polling fallback and viewing a completed scan.

**Response:**
```json
{
  "scanId": "string",
  "targetUrl": "string",
  "scanMode": "default | deep | custom",
  "status": "running | completed | failed",
  "progress": 0,
  "findings": [
    {
      "findingId": "string",
      "severity": "Critical | High | Medium | Low",
      "title": "string",
      "description": "string",
      "remediation": "string",
      "evidence": "string",
      "createdAt": "ISO8601 string"
    }
  ]
}
```
`severity` is a fixed enum — `Critical | High | Medium | Low` only, no free-text values. This keeps frontend severity badges and sorting deterministic.

#### `GET /report/{scanId}`

**Response:** `Report` shape —
```json
{
  "scanId": "string",
  "targetUrl": "string",
  "scanMode": "default | deep | custom",
  "summary": {
    "riskScore": 0,
    "totalFindings": 0,
    "bySeverity": { "Critical": 0, "High": 0, "Medium": 0, "Low": 0 }
  },
  "findings": []
}
```
`findings` uses the same finding shape as `GET /scan/{scanId}`.

#### `GET /report/{scanId}/export`

Returns a binary PDF stream, not JSON. `Content-Type: application/pdf`, with a `Content-Disposition` header suggesting filename `armorguard-report-{scanId}.pdf`.

#### `GET /sessions`

**Response:**
```json
{
  "sessions": [
    {
      "scanId": "string",
      "targetUrl": "string",
      "date": "ISO8601 string",
      "severitySummary": { "Critical": 0, "High": 0, "Medium": 0, "Low": 0 }
    }
  ]
}
```

### WebSocket Contracts

**`/ws/scan/{scanId}`** — server → client events only (no client → server messages needed beyond the initial connection).

| Event | Payload |
| --- | --- |
| `scan_started` | `{ "scanId": "string" }` |
| `agent_reasoning` | `{ "text": "string" }` |
| `tool_status` | `{ "tool": "string", "status": "running \| done", "message": "string" }` |
| `finding_discovered` | Same `Finding` shape as `GET /scan/{scanId}` |
| `intent_drift_detected` | `{ "errorCode": "string", "blockReason": "string", "driftClassification": "prompt_injection \| hallucination", "attemptedAction": "string" }` |
| `agent_halted` | `{ "reason": "string" }` |
| `scan_completed` | `{ "scanId": "string" }` |
| `scan_failed` | `{ "reason": "string" }` |

`driftClassification` mirrors the two categories defined in section 3 (Conventions) / the Governance section of the build plan — out-of-scope action = `prompt_injection`, valid action with wrong parameters = `hallucination`. Keep this in sync if those rules change.

### Database Schema (Supabase / PostgreSQL)

`Report` has no dedicated table — it is computed at read time by aggregating `scans` + `findings` (`riskScore` and `bySeverity` are derived, not stored). Everything else below maps directly to the data models in section 6.

```sql
CREATE TABLE consent_records (
  consent_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_url     TEXT NOT NULL,
  operator_ip    TEXT NOT NULL,
  timestamp      TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged   BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE scans (
  scan_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_url     TEXT NOT NULL,
  scan_mode      TEXT NOT NULL CHECK (scan_mode IN ('default', 'deep', 'custom')),
  selected_tools TEXT[],
  status         TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')) DEFAULT 'running',
  progress       INTEGER NOT NULL DEFAULT 0,
  consent_id     UUID REFERENCES consent_records(consent_id),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
  finding_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id        UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  severity       TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
  title          TEXT NOT NULL,
  description    TEXT NOT NULL,
  remediation    TEXT NOT NULL,
  evidence       TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log_events (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id        UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  event_type     TEXT NOT NULL,
  message        TEXT NOT NULL,
  metadata       JSONB,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE intent_drift_events (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id              UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  error_code           TEXT NOT NULL,
  block_reason         TEXT NOT NULL,
  drift_classification TEXT NOT NULL CHECK (drift_classification IN ('prompt_injection', 'hallucination')),
  attempted_action     TEXT NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for the lookups the API actually does
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_audit_log_scan_id ON audit_log_events(scan_id);
CREATE INDEX idx_drift_events_scan_id ON intent_drift_events(scan_id);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC); -- for GET /sessions ordering
```

**Notes:**
- `scans.consent_id` is nullable — local/private-IP targets never create a `ConsentRecord`, so this stays `NULL` for those scans.
- `riskScore` and `bySeverity` in the `GET /report/{scanId}` response are computed with a `GROUP BY severity` query over `findings`, not stored as columns.
- `GET /sessions` reads `scans` joined with a `findings` aggregate for the severity summary — no separate sessions table needed.

---

## 8. Folder Structure

```
root/
├── frontend/         # Next.js app — dashboard, scan flow, live scan view, report view
├── backend/          # FastAPI service — API routes, WebSocket server, Supabase connection, PDF export
├── agent/            # PydanticAI agent, tool wrappers, ArmorIQ governance integration (runs inside the backend service at deploy time)
├── docs/             # PROJECT.md and any supporting documentation
├── infrastructure/   # Dockerfiles, docker-compose.yml, env templates
```

| Folder | Purpose | Owner |
| --- | --- | --- |
| `frontend/` | Dashboard, scan controls, live scan terminal, report view, PDF export trigger | Kirti |
| `backend/` | API routes, WebSocket server, Supabase integration, report assembly, PDF generation | Sujat |
| `agent/` | PydanticAI agent definition, tool wrappers (Nmap/Nuclei/sqlmap/httpx), ArmorIQ governance wrapping, drift handling | Parth |
| `docs/` | PROJECT.md and related documentation | Shared — see section 13 (Change Control) |
| `infrastructure/` | Docker Compose setup, demo target container, deployment config | Kanishk (demo target/integration), with Sujat for backend container config |

> **Note:** `agent/` is a logical/ownership boundary, not a separate deployable service — per section 4 (Tech Stack), backend and agent run as a single Python process (FastAPI + PydanticAI).

---

## 9. Ownership & Build Plan

This is the team's live project tracker. Each person checks off tasks/subtasks as they complete them so both teammates and AI assistants can see current state at a glance.

### Kirti — Frontend

**Responsibilities:** Next.js dashboard, scan flow UI, live scan view, report view, PDF export trigger.

**Dependencies:** Backend REST endpoints (section 7) and the `/ws/scan/{scanId}` WebSocket contract (section 7) for live data; data shapes from section 6.

**Do Not Modify:** `backend/`, `agent/`, database schema, API/WebSocket contracts (section 7) without team approval.

**Build Tracker:**

- [ ] Project setup
  - [x] Init Next.js 14 with App Router
  - [x] Configure Tailwind + shadcn/ui
  - [ ] Set up native WebSocket client
  - [ ] Connect to backend base URL via env variable

- [ ] Dashboard
  - [ ] Navbar
    - [ ] Logo
    - [ ] Hamburger menu — slides open session history sidebar
  - [ ] Session history sidebar
    - [ ] List of past scans (target, date, severity summary)
    - [ ] Click session → opens its report view
  - [ ] Mini terminal window
    - [ ] Floating, minimizable
    - [ ] Shows current tool running and its live logs
    - [ ] Updates via WebSocket in real time

- [ ] Scan Flow (Home / Input view)
  - [ ] Target URL input field
  - [ ] Auto-detect local vs public target
  - [ ] Scan mode selector — Default / Deep / Custom
  - [ ] Tool checklist (visible only in Custom mode)
  - [ ] Consent gate — appears for public targets, blocks scan start until acknowledged
  - [ ] Start scan button

- [ ] Live Scan View
  - [ ] Active mission status panel (target, scan mode, current status)
  - [ ] LLM reasoning stream — streams agent thinking in real time
  - [ ] Per-tool status updates (e.g. "Nmap scan done, starting Nuclei now")
  - [ ] Incident panel — slides in inline on ArmorIQ block, shows attempted action, error_code, block reason, drift classification

- [ ] Report View
  - [ ] Severity-scored findings list (Critical / High / Medium / Low)
  - [ ] Per-finding detail (root cause + remediation)
  - [ ] Executive risk summary
  - [ ] Interactive vulnerability graph — React Flow, nodes color-coded by severity, click node opens full finding detail
  - [ ] PDF export integration

---

### Sujat — Backend

**Responsibilities:** FastAPI service scaffolding, REST + WebSocket contracts, Supabase integration, report assembly, audit trail, PDF export. Hosts the agent (owned by Parth) as a background task within the same service.

**Dependencies:** Agent must be invocable as a background task (Parth); ArmorIQ block/halt signals must propagate up to the WebSocket handler (Parth); demo target container must be reachable from the backend container (Kanishk).

**Do Not Modify:** `frontend/`, agent tool logic and ArmorIQ wrapping internals (Parth's area) without flagging it first, demo target app code (Kanishk's area).

**Build Tracker:**

- [/] Infrastructure
  - [x] Init FastAPI project
  - [x] Configure native WebSocket server
  - [ ] Connect to Supabase
  - [x] Set up env config (.env + dotenv)
  - [x] Write Dockerfile (install Nmap, Nuclei, sqlmap, httpx inside container)
  - [x] Write docker-compose.yml (frontend + backend, backend in privileged mode — pending the `-sT` test in section 4)

- [x] Consent flow
  - [x] Target type detection (local IP range vs public URL)
  - [x] `POST /consent` endpoint — stores `ConsentRecord` (target URL, operator IP, timestamp, acknowledgment)
  - [x] Consent validation middleware — blocks `/scan` for public targets without a valid `ConsentRecord`

- [x] APIs — Scan management
  - [x] `POST /scan` endpoint — validates consent, creates `Scan` record, triggers agent
  - [x] `GET /scan/{id}` endpoint — returns current scan status and findings
  - [x] Scan status updates via WebSocket (stream findings + LLM reasoning as they arrive from the agent)

- [/] Reports
  - [x] Report assembly logic (aggregate findings, compute severity summary)
  - [x] Stream final report to frontend via WebSocket on scan completion
  - [ ] `GET /report/{scan_id}` endpoint — for session history, returns stored report data from Supabase

- [x] Session history
  - [x] `GET /sessions` endpoint — returns list of past scans (target, date, severity summary)

- [ ] Audit trail
  - [ ] Store `AuditLogEvent` on every agent tool call
  - [ ] Store `IntentDriftEvent` on every ArmorIQ block

- [/] PDF export
  - [x] `GET /report/{scan_id}/export` endpoint — generates and returns PDF of full report
  - [ ] Use WeasyPrint or ReportLab to generate PDF server-side from findings JSON

- [/] Agent integration (hosting)
  - [x] Run PydanticAI agent as FastAPI background task (no separate service)
  - [ ] Pass scan mode + selected tools + target into agent on scan start
  - [ ] Wire agent's findings + reasoning stream into the WebSocket handler in real time

---

### Parth — Agent + Governance

**Responsibilities:** PydanticAI agent definition and tool wrappers (Nmap, Nuclei, sqlmap, httpx), ArmorIQ SDK integration, intent drift detection/classification, agent halt logic, finding extraction.

**Dependencies:** Backend must provide the background-task invocation point and pass scan mode/tools/target on scan start (Sujat); WebSocket handler must be wired to receive agent reasoning/findings/drift events (Sujat); demo target's prompt injection payload (Kanishk) for validating drift detection end-to-end.

**Do Not Modify:** `frontend/`, REST/WebSocket route definitions outside the agent's emitted events (Sujat's area), demo target app code (Kanishk's area).

**Build Tracker:**

- [/] Project scaffolding
  - [x] Install PydanticAI + dependencies
  - [x] Install ArmorIQ SDK
  - [ ] Configure ArmorIQ client (API key, agent ID)
  - [x] Configure LLM provider via env variable — Groq/Gemini for build phase, swappable to Claude for finals (PydanticAI model string must not be hardcoded)

- [ ] Tool definitions (each wrapped with ArmorIQ `capture_plan` → `get_intent_token` → `invoke`)
  - [ ] Nmap tool — port scanning, runs subprocess Nmap, parses output into findings
  - [ ] Nuclei tool — misconfigs, headers, admin panels, CVEs, runs Nuclei CLI with appropriate templates
  - [ ] sqlmap tool — SQL injection detection (Deep scan only)
  - [ ] httpx tool — custom HTTP probes not covered by Nuclei
  - [ ] Scan mode filter — Default runs Nmap + Nuclei + httpx, Deep adds sqlmap + aggressive Nuclei templates, Custom runs user-selected tools

- [ ] Agent loop
  - [ ] PydanticAI agent definition with all tools registered
  - [ ] Tool call → ArmorIQ `capture_plan` → `get_intent_token` → `invoke` flow
  - [ ] Finding extraction from tool results
  - [ ] Stream findings + LLM reasoning back to the WebSocket handler in real time
  - [ ] Agent halt on ArmorIQ block (`VerificationError`)

- [ ] ArmorIQ integration
  - [ ] Wrap every tool call with ArmorIQ validation middleware
  - [ ] Handle ArmorIQ block response — halt agent, emit `IntentDriftEvent`

- [ ] Governance policy (ArmorIQ — runs inside the backend service)
  - [ ] Policy setup
    - [ ] Define engagement scope — approved target, approved tool list per scan mode
    - [ ] Configure ArmorIQ client with API key and agent ID
  - [ ] Drift classification rules
    - [ ] Out-of-scope action attempted → classify as `prompt_injection`
    - [ ] Valid action, wrong parameters → classify as `hallucination`/drift
    - [ ] Document rules so the frontend incident panel labels correctly
  - [ ] Demo prompt injection setup
    - [ ] Author the payload text and embed it in the demo target's page content
    - [ ] Confirm ArmorIQ intercepts, halts, and streams the incident payload correctly

---

### Kanishk — Demo Target + Integration/Rehearsal

**Responsibilities:** Deliberately vulnerable demo web app (third Docker container), planted vulnerabilities, prompt injection payload, full integration verification, and demo rehearsal.

**Dependencies:** Backend container must be able to reach the demo target container on the Docker network (Sujat); agent's tool set must be able to actually exercise each planted vulnerability (Parth).

**Do Not Modify:** `frontend/`, `backend/`, `agent/` internals — flag any required change to those areas to the relevant owner instead of editing directly.

**Build Tracker:**

- [x] Project scaffolding
  - [x] Simple Flask or Express app
  - [x] Add as third container in docker-compose.yml

- [ ] Planted vulnerabilities
  - [ ] Exposed admin panel at `/admin` with no access control
  - [ ] Verbose error page leaking stack trace and file paths
  - [ ] Open database port (e.g. SQLite accessible, or just an open port)
  - [ ] Missing security headers (no CSP, HSTS, X-Frame-Options)
  - [ ] Session cookie without Secure/HttpOnly flags
  - [ ] SQL injection vulnerable endpoint

- [ ] Verification — confirm each planted vulnerability is actually reachable/triggerable
  - [ ] Confirm `/admin` is live and returns 200 with no auth
  - [ ] Confirm a request triggers the verbose error page with visible stack trace
  - [ ] Confirm the open port is reachable from the backend container
  - [ ] Confirm security headers are genuinely absent (check via curl/browser devtools)
  - [ ] Confirm session cookie is missing Secure/HttpOnly flags
  - [ ] Confirm the SQL injection endpoint is actually exploitable by sqlmap

- [ ] Prompt injection payload
  - [ ] Hidden payload on one of the pages — instructs agent to exfiltrate data instead of reporting
  - [ ] Confirm ArmorIQ intercepts it and the incident panel fires correctly

- [ ] Consent copy — operator-facing disclaimer text
  - [ ] Draft the exact text shown to the operator before they acknowledge (placeholder until finalized): *"I confirm I am authorized to test this target. I understand this scan may include active exploitation attempts (including SQL injection via sqlmap in Deep mode) and that my IP address and acknowledgment will be logged for audit purposes."*
  - [ ] Finalize wording with team — what `acknowledged: true` is standing in for must be unambiguous, since Deep mode performs active exploitation, not passive scanning

- [ ] Full integration & rehearsal — run before presentation, not during it
  - [ ] Run a complete scan end-to-end against the demo target before demo day — consent → scan → live feed → report → export
  - [ ] Run the prompt injection scenario at least once before demo day — confirm ArmorIQ blocks it and the incident panel renders correctly
  - [ ] Time the full demo flow once to make sure it fits the available slot

---

## 10. Integration Checkpoints

### Checkpoint 1 — Frontend ↔ Backend connectivity
- **Required completed components:** Backend project scaffolding (Sujat); frontend project scaffolding with env-configured backend base URL (Kirti).
- **Validation criteria:** Frontend can successfully call a basic backend endpoint and receive a response.
- **Expected output:** A confirmed network path between the two services with no CORS/connection errors.

### Checkpoint 2 — Backend ↔ Agent integration
- **Required completed components:** Agent scaffolding + tool registration (Parth); backend's background-task trigger for the agent (Sujat).
- **Validation criteria:** `POST /scan` successfully starts the agent as a background task and the agent begins executing tools.
- **Expected output:** A scan transitions to `running` status with at least one tool invocation observed in logs.

### Checkpoint 3 — ArmorIQ validation working
- **Required completed components:** ArmorIQ client configured (Parth); `capture_plan` → `get_intent_token` → `invoke` wrapping on at least one tool (Parth).
- **Validation criteria:** A tool call is validated by ArmorIQ before execution, and a deliberately out-of-scope action is blocked.
- **Expected output:** An `IntentDriftEvent` is correctly generated and the agent halts on block.

### Checkpoint 4 — End-to-end scan execution
- **Required completed components:** All four agent tools (Nmap, Nuclei, sqlmap, httpx) wired in (Parth); scan status streaming via WebSocket (Sujat); Live Scan View rendering the stream (Kirti).
- **Validation criteria:** A full scan against the demo target runs from `POST /scan` to `scan_completed` without manual intervention.
- **Expected output:** Findings are extracted and visible in the Live Scan View in real time.

### Checkpoint 5 — Report generation and storage
- **Required completed components:** Report assembly logic (Sujat); `GET /report/{scanId}` and `GET /report/{scanId}/export` (Sujat); Report View (Kirti).
- **Validation criteria:** A completed scan produces a stored report retrievable via the API and renders correctly in the frontend, including PDF export.
- **Expected output:** A downloadable PDF matching the on-screen report.

### Checkpoint 6 — Full demo rehearsal
- **Required completed components:** Demo target with all planted vulnerabilities and the prompt injection payload (Kanishk); full frontend flow (Kirti); full backend + agent + governance flow (Sujat, Parth).
- **Validation criteria:** A complete run-through — consent → scan → live feed → ArmorIQ block on the injection payload → report → export — completes successfully within the demo time slot.
- **Expected output:** A timed, successful rehearsal with no manual workarounds.

### Checkpoint 7 — Demo lock
- **Required completed components:** All items in the Definition of Done checklist (section 12).
- **Validation criteria:** No outstanding blocking bugs; rehearsal from Checkpoint 6 passed.
- **Expected output:** Demo lock declared — only bug fixes permitted from this point per section 12.

---

## 11. Fallback Plan

| If… fails | Fallback action | Impact |
| --- | --- | --- |
| PydanticAI agent | Scripted scan — hardcoded tool sequence, ArmorIQ still validates each call | Demo proceeds without live LLM reasoning narration, but governance story stays intact |
| ArmorIQ | Mock validation layer — logs every tool call, allows execution, demo story holds | Loses real-time blocking, but the audit trail and demo narrative still function |
| WebSockets | Polling — frontend polls `GET /scan/{id}` every 2 seconds | Live feed becomes near-real-time instead of instant; no loss of functionality |
| Nuclei | Nmap + httpx only — still surfaces port and HTTP findings | Reduced finding coverage, but scan still completes and produces a report |
| sqlmap | Skip SQL injection step, rest of scan completes normally | Deep mode loses one finding category; Default mode unaffected |
| Supabase | In-memory store — findings held in server state for demo duration | No persistence across restarts, but the live demo flow is unaffected |

---

## 12. Definition of Done & Demo Lock

**Demo-ready checklist:**
- [ ] End-to-end scan works (consent → scan → live feed → report)
- [ ] Findings are generated for the demo target's planted vulnerabilities
- [ ] ArmorIQ blocks are demonstrated against the prompt injection payload
- [ ] Report generation works (`GET /report/{scanId}`)
- [ ] Session history works (`GET /sessions`)
- [ ] PDF export works (`GET /report/{scanId}/export`)
- [ ] Demo target validated (all planted vulnerabilities confirmed reachable/triggerable per section 9)
- [ ] Full rehearsal completed and timed to fit the demo slot

**Demo lock policy:** Once the checklist above is fully complete and the full rehearsal (Checkpoint 6, section 10) has passed, the project enters demo lock.

**After demo lock:**
- ✅ Bug fixes allowed
- ❌ No new features
- ❌ No architecture changes
- ❌ No contract changes

---

## 13. Change Control

- PROJECT.md is the repository source of truth.
- Architecture changes (section 5) require team approval.
- Contract changes (section 7) require team approval.
- Schema changes (section 6 / database schema in section 7) require team approval.
- Ownership changes (section 9) require team approval.
- Any approved change must be reflected immediately in the relevant section of this document.
- No silent edits to shared project context — if a change affects another teammate's work, that teammate must be informed before the document is updated.
