# ArmorGuard — Master Project Document

**File:** PROJECT.md
**Purpose:** Single source of truth for project scope, architecture, contracts, conventions, ownership, and build progress. All teammates and AI coding assistants must treat this document as the authoritative reference for every decision.
**Audience:** All teammates and AI coding assistants.
**Status:** Draft
**Last Updated:** 2026-06-20 — Sujat

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Problem & Solution](#2-problem--solution)
- [3. Tech Stack](#3-tech-stack)
- [4. Architecture](#4-architecture)
- [5. Folder Structure](#5-folder-structure)
- [6. Data Models](#6-data-models)
- [7. Contracts](#7-contracts)
  - [7.1 REST APIs](#71-rest-apis)
  - [7.2 Real-time / WebSocket Events](#72-real-time--websocket-events)
  - [7.3 Internal Component Interfaces](#73-internal-component-interfaces)
  - [7.4 Database Schema](#74-database-schema)
- [8. Environment & Configuration](#8-environment--configuration)
- [9. Conventions](#9-conventions)
- [10. Ownership & Build Plan](#10-ownership--build-plan)
- [11. Integration Checkpoints](#11-integration-checkpoints)
- [12. Fallback Plan](#12-fallback-plan)
- [13. Definition of Done & Demo Lock](#13-definition-of-done--demo-lock)
- [14. Change Control](#14-change-control)

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

**Proposed solution:** An autonomous AI agent that runs real pentesting tools (Nmap, Katana, ffuf, Arjun, httpx, Nuclei, Nikto, sqlmap, Hydra) against a target, with every single tool call validated in real time by the ArmorIQ SDK before execution. If the agent's intent drifts from its authorized scope — whether from prompt injection or hallucination — ArmorIQ halts the agent immediately and surfaces the incident to the operator.

**Differentiators:**
- Two equal pillars in one system: autonomous AI-driven pentesting *and* defensive AI agent integrity governance — not just a scanner, but a scanner that polices its own agent's behavior.
- Real-time intent drift detection and halt, not a post-hoc log review.

---

## 3. Tech Stack

| Component | Technology |
| --- | --- |
| Frontend | React + Vite + Tailwind + shadcn/ui + Recharts + React Flow |
| Backend + Agent | FastAPI + LangGraph (single Python service) |
| Governance | ArmorIQ SDK (manually wrapped around every agent tool call) |
| Real-time | Native FastAPI WebSockets |
| Database | Supabase (PostgreSQL) |
| LLM | Groq `llama-3.3-70b-versatile` via LangChain (swappable via `LLM_PROVIDER` env var) |
| Scanner tools | Nmap, Katana, ffuf, Arjun, httpx, Nuclei, Nikto, sqlmap, Hydra — baked into Docker image at `/opt/tools` |
| Dev runtime | Docker Compose — single `docker-compose up` boots frontend + backend + demo-target containers |
| Deployment | Vercel (frontend) + Railway (backend) |

### Open Questions

- **Nmap privileged mode** — backend container currently runs in privileged mode for Nmap raw socket access. Not yet tested whether non-privileged `-sT` (TCP connect scan) covers the planted demo vulnerabilities adequately. — Owner: Sujat — Action: Test `-sT` before build day; if sufficient, drop privileged mode from docker-compose.yml entirely. [resolved: left in privileged mode — `-sT` was not tested in time]

---

## 4. Architecture

### High-Level Flow

```
User → Frontend → FastAPI → LangGraph Agent → ArmorIQ → Tools → Findings → Supabase → Frontend
```

**Step by step:**
1. User enters target + selects scan mode (Default / Deep / Custom) on frontend.
2. Frontend detects target type — local skips consent, public triggers consent gate.
3. Consent acknowledged → `POST /consent` → FastAPI stores `ConsentRecord`.
4. `POST /scan` with target + scan mode + selected tools → FastAPI creates `Scan` record in Supabase.
5. FastAPI triggers the LangGraph agent as a background task, opens a WebSocket to the frontend.
6. Agent runs tools based on scan mode — every tool call is wrapped with ArmorIQ `capture_plan` → `get_intent_token` → `invoke`.
7. LLM reasoning + tool call status streams via WebSocket → frontend terminal window updates live.
8. If ArmorIQ detects intent drift → agent halts, drift event streamed to frontend as an alert.
9. Agent finishes → FastAPI assembles the report, stores it in Supabase, sends the final assessment to the frontend.

**Scan Modes:**
- **Default** — Nmap, Katana, ffuf, httpx, Nuclei (discovery + common misconfigs).
- **Deep** — everything in Default + Arjun, Nikto, sqlmap, Hydra (full attack surface, credential testing, injection).
- **Custom** — user selects individual tools from a checklist (any subset of the deep tool list).

### Component Responsibilities

- **Frontend** — React + Vite dashboard, scan controls (target input, mode selector, consent gate), live scan terminal/reasoning stream, and the report view (findings list, risk summary, vulnerability graph, PDF export trigger).
- **Backend** — FastAPI service exposing all REST and WebSocket contracts (§7), persists `ConsentRecord`/`Scan`/`Finding`/`Report` data to Supabase, assembles reports, and generates PDF exports.
- **Agent** — LangGraph agent running as a FastAPI background task; runs the registered tools (Nmap, Katana, ffuf, Arjun, httpx, Nuclei, Nikto, sqlmap, Hydra) according to scan mode, extracts findings from tool output, and streams reasoning + findings back through the WebSocket handler via the `broadcast` callback.
- **Governance Layer** — ArmorIQ SDK, initialized inside the same backend service. Wraps every agent tool call in `capture_plan` → `get_intent_token` → `invoke`; classifies and halts on intent drift (prompt injection or hallucination), emitting an `IntentDriftEvent`.
- **Database** — Supabase (PostgreSQL). Stores `ConsentRecord`, `Scan`, `Finding`, `AuditLogEvent`, and `IntentDriftEvent` rows. `Report` is computed at read time, not stored.
- **Demo Target** — A deliberately vulnerable third Docker container with planted vulnerabilities and an embedded prompt injection payload, used to exercise the full pentest + governance flow during the demo.

---

## 5. Folder Structure

```
root/
├── client/           # React/Vite app — dashboard, scan flow, live scan view, report view
├── server/           # FastAPI service + agent — API routes, WebSocket server, Supabase connection, PDF export
│   └── agent/        # LangGraph agent, tool wrappers, ArmorIQ governance integration
├── demo-target/      # Deliberately vulnerable Flask app for demos (standalone, not modified)
├── docs/             # PROJECT.md and any supporting documentation
├── scripts/          # Dev/ops utilities: tool install scripts, ffuf wordlists, scan runner
```

| Folder | Purpose | Owner |
| --- | --- | --- |
| `client/` | Dashboard, scan controls, live scan terminal, report view, PDF export trigger | Kirti |
| `server/` | API routes, WebSocket server, Supabase integration, report assembly, PDF generation | Sujat |
| `server/agent/` | LangGraph agent definition, tool wrappers (Nmap/Nuclei/sqlmap/httpx), ArmorIQ governance wrapping, drift handling | Parth |
| `demo-target/` | Deliberately vulnerable Flask app — planted vulnerabilities + prompt injection payload | Kanishk |
| `docs/` | PROJECT.md and related documentation | Shared — see §14 (Change Control) |
| `scripts/` | Dev/ops utilities: tool install scripts, ffuf wordlists, scan runner | Kanishk + Sujat jointly |

> **Note:** `server/agent/` is a logical/ownership boundary, not a separate deployable service — per §3 (Tech Stack), server and agent run as a single Python process (FastAPI + LangGraph).

---

## 6. Data Models

These definitions are the single source of truth referenced by the contracts in §7. No field should be redefined elsewhere.

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

These contracts are the coordination mechanism for parallel development. Each owner builds their component against the shapes defined here — not against a running implementation. Push when ready; other owners integrate after the PR merges. Any change requires team agreement per §14.

All request/response bodies reference the data models in §6 rather than redefining fields inline.

### 7.1 REST APIs

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

---

### 7.2 Real-time / WebSocket Events

**`/ws/scan/{scanId}`** — server → client only (no client → server messages needed beyond the initial connection).

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

`driftClassification` mirrors the two categories in §9 (Logging Convention) — out-of-scope action = `prompt_injection`, valid action with wrong parameters = `hallucination`. Keep this in sync if those rules change.

---

### 7.3 Internal Component Interfaces

#### RunScan

**Signature:** `async def run_scan(scan_id: str, target_url: str, scan_mode: str, selected_tools: list, broadcast) -> None`

**Published by:** Parth — `server/agent/agent.py`

**Consumed by:** Sujat (backend, as a FastAPI background task triggered by `POST /scan`)

**DB write rule:** Backend handles all Supabase writes. The agent must **not** write to the database directly — it emits every §7.2 event by calling `await broadcast({"event": "<name>", "data": {...}})` and the backend handler persists `Finding`, `AuditLogEvent`, and `IntentDriftEvent` rows from what it receives.

**Constraints:** Must be called after the `Scan` record is created in Supabase, so `scan_id` is a valid foreign key for any rows the backend persists on the agent's behalf.

**Events emitted:** All events listed in §7.2, emitted via the `broadcast` callback in the order they occur during the scan. The backend does not filter or reorder them.

---

### 7.4 Database Schema

`Report` has no dedicated table — it is computed at read time by aggregating `scans` + `findings` (`riskScore` and `bySeverity` are derived, not stored). Everything else below maps directly to the data models in §6.

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

## 8. Environment & Configuration

### Backend (`server/.env`)

| Variable | Purpose | Source | Required |
|---|---|---|---|
| `SUPABASE_URL` | Supabase project URL | Supabase dashboard → Project Settings → API → Project URL | Yes |
| `SUPABASE_KEY` | Supabase service-role key (bypasses RLS) | Supabase dashboard → Project Settings → API → service_role key | Yes |
| `ARMORIQ_API_KEY` | ArmorIQ authentication key | platform.armoriq.ai → API Keys | Yes |
| `ARMORIQ_AGENT_ID` | ArmorIQ agent ID scoped to this project's policy | platform.armoriq.ai → Agents | Yes |
| `ARMORIQ_MOCK` | Set to `true` to disable real ArmorIQ enforcement (local deterministic backstop only) | Set manually in `.env` | No — defaults to real enforcement |
| `LLM_PROVIDER` | Which LLM backend to use: `gemini` \| `groq` \| `claude` \| `ollama` | Set manually in `.env` | Yes |
| `GEMINI_API_KEY` | Gemini API key (required when `LLM_PROVIDER=gemini`) | Google AI Studio → API Keys | Conditional |
| `GROQ_API_KEY` | Groq API key (required when `LLM_PROVIDER=groq`) | console.groq.com → API Keys | Conditional |
| `CLAUDE_API_KEY` | Anthropic API key (required when `LLM_PROVIDER=claude`) | console.anthropic.com → API Keys | Conditional |
| `OLLAMA_BASE_URL` | Ollama server URL (required when `LLM_PROVIDER=ollama`) | Set manually — default `http://localhost:11434` | Conditional |
| `OLLAMA_MODEL` | Ollama model name (required when `LLM_PROVIDER=ollama`) | Set manually — e.g. `llama3.2` | Conditional |

**Secrets — never commit to git:** `SUPABASE_KEY`, `ARMORIQ_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `CLAUDE_API_KEY`

**Safe local defaults:** `ARMORIQ_MOCK=true` lets the backend run without a real ArmorIQ account. `LLM_PROVIDER=gemini` with a free-tier key is the standard local dev setup.

**Required to start:** `SUPABASE_URL`, `SUPABASE_KEY`, `ARMORIQ_API_KEY`, `ARMORIQ_AGENT_ID`, `LLM_PROVIDER`, and whichever key matches the chosen provider.

### Frontend (`client/.env`)

| Variable | Purpose | Source | Required |
|---|---|---|---|
| `VITE_BACKEND_URL` | Base URL of the FastAPI backend | Set manually — `http://localhost:8000` for local dev; Railway URL for production | Yes |

**Safe local default:** `VITE_BACKEND_URL=http://localhost:8000`

---

## 9. Conventions

These rules apply across the entire codebase regardless of who or what (human or AI) is writing the code. They prevent naming drift and silent interface mismatches between components built in parallel.

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

**Wire format:** All JSON keys sent over the network use `camelCase` — enforced on the backend by `CamelModel` in `server/main.py`, even though the Python internals use `snake_case`.

### Branch Naming

```
feature/client-dashboard
feature/server-scan-api
feature/agent-tools
fix/websocket-reconnect
```

### Commit Format

```
feat(client): add live scan terminal
feat(agent): implement nuclei tool
fix(server): validate consent record
docs(project): update architecture
```

Valid scopes: `client`, `server`, `agent`, `demo-target`, `scripts`, `project`.

### Standard Error Response

All APIs follow one consistent error shape:

```json
{
  "error": "string (machine-readable error code, e.g. consent_required)",
  "message": "string (human-readable description)"
}
```

Reserved codes all owners must know: `consent_required`, `tools_required`, `validation_error`. Every API error in the system must follow this exact `error` + `message` shape — no exceptions.

### Logging Convention

| Level | Use For |
| --- | --- |
| `INFO` | Normal lifecycle events — scan started, tool started/finished, report generated |
| `WARNING` | Recoverable issues — a tool failed but the scan continues (see Fallback Plan, §12) |
| `ERROR` | Unrecoverable failures — agent crash, Supabase write failure, scan marked `failed` |
| `SECURITY` | Any ArmorIQ block / intent drift event — always paired with an `IntentDriftEvent` row |

**Log ownership:** The backend service (Sujat) owns log emission for all backend and agent code paths, since the agent runs inside the same FastAPI process.

**Storage:** `INFO`/`WARNING`/`ERROR` go to stdout inside the container (captured by `docker compose logs`). `SECURITY` logs are additionally persisted as `AuditLogEvent` / `IntentDriftEvent` rows in Supabase so they survive restarts and are queryable for the audit trail.

### Data Write Ownership

- **Backend (Sujat)** is the sole writer for all Supabase tables: `consent_records`, `scans`, `findings`, `audit_log_events`, `intent_drift_events`. No other component may write to the database directly.
- **Agent (Parth)** must not write to the database. It returns data to the backend by calling `await broadcast({"event": "...", "data": {...}})` via the callback defined in §7.3. The backend handler receives these events and handles all persistence.

### Design System & Visual Tokens

**Component library:** shadcn/ui (only — no mixing with other component libraries)

**Color palette** (dark mode is the primary UI):

| Token | CSS variable | Hex (dark) | Use for |
|---|---|---|---|
| `background` | `--background` | `#1f1f1f` | Page / app background |
| `card` | `--card` | `#262626` | Cards, panels, modals |
| `border` | `--border` | `#333333` | Dividers, input borders |
| `foreground` | `--foreground` | `#ebebeb` | Headings, body text |
| `muted-foreground` | `--muted-foreground` | `#8c8c8c` | Labels, timestamps, captions |
| `primary` | `--primary` | `#d97959` | Primary actions, links, active states (warm terracotta) |
| `destructive` | `--destructive` | `#ef4444` | Error states, destructive actions |

**Severity colors** (used in finding badges, graph nodes, and left-border accents):

| Severity | Hex | Tailwind class |
|---|---|---|
| Critical | `#ef4444` | `text-red-400` / `bg-red-500/10` |
| High | `#f97316` | `text-orange-400` / `bg-orange-500/10` |
| Medium | `#eab308` | `text-yellow-400` / `bg-yellow-500/10` |
| Low | `#22c55e` | `text-green-400` / `bg-green-500/10` |

**Typography:**

| Role | Font | Size | Weight |
|---|---|---|---|
| Heading | Inter | `text-2xl` / `text-3xl` | 600–700 |
| Body | Inter | `text-sm` / `text-base` | 400 |
| Monospace / terminal | JetBrains Mono | `text-xs` / `text-sm` | 400 |

**Spacing & radius:** Default Tailwind spacing scale, no custom overrides. Base border-radius: `0.375rem` (`rounded-md` in Tailwind). Cards use `rounded-xl`.

**Rule:** No one-off hex values, font sizes, or spacing values in component code. If a value is not in this table, add it here first and reference the token.

### CORS Policy

- **Local dev:** Allow `http://localhost:5173` (Vite) and `http://localhost:8000`
- **Production:** Allow the Vercel frontend URL only (set explicitly — not wildcard)
- **Methods:** GET, POST, OPTIONS
- **Headers:** Content-Type, Authorization
- **Credentials:** `allow_credentials=True` (required for cookie-based auth if added later)

**Current implementation:** `server/main.py` sets `allow_origins=["*"]` — acceptable for local development but must be tightened to the explicit Vercel URL before any production deployment. Backend owner (Sujat) owns CORS configuration.

### AI Assistant Rules

AI assistants working on this codebase must:
- Not create new routes or endpoints outside the contracts in §7.
- Not modify contracts (§7) without team approval per §14.
- Not introduce new dependencies without approval.
- Not modify another owner's folder without flagging the relevant owner first — see §10 for ownership boundaries.
- Not alter architecture (§4), data models (§6), database schema (§7.4), or environment config (§8) without approval.
- Treat this document as the source of truth. If something in the code conflicts with this document, flag the discrepancy rather than silently resolving it.

---

## 10. Ownership & Build Plan

This is the team's live project tracker. Each owner checks off tasks as they complete them — both teammates and AI assistants use this to see current state at a glance.

The tech lead (Sujat) scaffolded the base structure of every owner's folder before handoff. Those tasks are pre-checked `[x]` in each build tracker below. Each owner works on their own branch and builds against the contracts in §7 — not against a running service. When work is ready: push, open PR, get it merged. Other owners pull main and resolve any conflicts on their branch.

---

### Kirti — Frontend

**Scope:** Next.js dashboard, scan flow UI, live scan view, report view, PDF export trigger — everything inside `client/`.

**Interfaces Published**

- None — frontend does not publish interfaces to other components.

**Interfaces Consumed**

| Interface | Published by | Defined in |
|---|---|---|
| `POST /consent` | Sujat | §7.1 |
| `POST /scan` | Sujat | §7.1 |
| `GET /scan/{scanId}` | Sujat | §7.1 |
| `GET /report/{scanId}` | Sujat | §7.1 |
| `GET /report/{scanId}/export` | Sujat | §7.1 |
| `GET /sessions` | Sujat | §7.1 |
| `/ws/scan/{scanId}` WebSocket | Sujat | §7.2 |

**Do Not Touch:** `server/`, `server/agent/`, database schema, API/WebSocket contracts (§7) without flagging Sujat first.

**Build Tracker:**

- [ ] Project setup
  - [x] Init React + Vite with Tailwind + shadcn/ui
  - [ ] Set up native WebSocket client
  - [ ] Connect to backend base URL via `VITE_BACKEND_URL` env variable

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

**Scope:** FastAPI service scaffolding, REST + WebSocket contracts, Supabase integration, report assembly, audit trail, PDF export — everything inside `server/` excluding `server/agent/`.

**Interfaces Published**

- All REST endpoints in §7.1 — see §7.1
- `/ws/scan/{scanId}` WebSocket server — see §7.2
- `broadcast` callback (passed as parameter into `run_scan`) — see §7.3

**Interfaces Consumed**

| Interface | Published by | Defined in |
|---|---|---|
| `run_scan(scan_id, target_url, scan_mode, selected_tools, broadcast)` | Parth | §7.3 |

**Do Not Touch:** `client/`, agent tool logic and ArmorIQ wrapping internals (`server/agent/` — Parth's area) without flagging Parth first, `demo-target/` (Kanishk's area).

**Build Tracker:**

- [x] Infrastructure
  - [x] Init FastAPI project
  - [x] Configure native WebSocket server
  - [x] Connect to Supabase
  - [x] Set up env config (.env + dotenv)
  - [x] Write Dockerfile (install Nmap, Nuclei, sqlmap, httpx inside container)
  - [x] Write docker-compose.yml (frontend + backend, backend in privileged mode)

- [x] Consent flow
  - [x] Target type detection (local IP range vs public URL)
  - [x] `POST /consent` endpoint — stores `ConsentRecord` (target URL, operator IP, timestamp, acknowledgment)
  - [x] Consent validation middleware — blocks `/scan` for public targets without a valid `ConsentRecord`

- [x] APIs — Scan management
  - [x] `POST /scan` endpoint — validates consent, creates `Scan` record, triggers agent
  - [x] `GET /scan/{id}` endpoint — returns current scan status and findings
  - [x] Scan status updates via WebSocket (stream findings + LLM reasoning as they arrive from the agent)

- [x] Reports
  - [x] Report assembly logic (aggregate findings, compute severity summary)
  - [x] Stream final report to frontend via WebSocket on scan completion
  - [x] `GET /report/{scan_id}` endpoint — for session history, returns stored report data from Supabase

- [x] Session history
  - [x] `GET /sessions` endpoint — returns list of past scans (target, date, severity summary)

- [x] Audit trail
  - [x] Store `AuditLogEvent` on every agent tool call
  - [x] Store `IntentDriftEvent` on every ArmorIQ block

- [x] PDF export
  - [x] `GET /report/{scan_id}/export` endpoint — generates and returns PDF of full report
  - [x] Use ReportLab to generate PDF server-side from findings JSON

- [x] Agent integration (hosting)
  - [x] Import and invoke `run_scan` from `server/agent/agent.py` as a FastAPI background task
  - [x] Pass `scan_id`, `target_url`, `scan_mode`, `selected_tools`, and `broadcast` callback into `run_scan` on scan start
  - [x] Wire agent's broadcast events into the WebSocket handler and Supabase writes in real time

---

### Parth — Agent + Governance

**Scope:** LangGraph agent definition and tool wrappers (Nmap, Katana, ffuf, Arjun, httpx, Nuclei, Nikto, sqlmap, Hydra), ArmorIQ SDK integration, intent drift detection/classification, agent halt logic, finding extraction — everything inside `server/agent/`.

**Interfaces Published**

- `run_scan(scan_id, target_url, scan_mode, selected_tools, broadcast) -> None` — see §7.3

**Interfaces Consumed**

| Interface | Published by | Defined in |
|---|---|---|
| `broadcast(event)` callback | Sujat | §7.3 |

**Do Not Touch:** `client/`, REST/WebSocket route definitions in `server/main.py` (Sujat's area), `demo-target/` (Kanishk's area).

**Build Tracker:**

- [x] Project scaffolding
  - [x] Install LangGraph + LangChain + dependencies
  - [x] Install ArmorIQ SDK
  - [x] Configure ArmorIQ client (API key, agent ID)
  - [x] Configure LLM provider via `LLM_PROVIDER` env variable — Groq for build phase, swappable to Claude for finals (model string must not be hardcoded)

- [x] Tool definitions (each wrapped with ArmorIQ `capture_plan` → `get_intent_token` → `invoke`)
  - [x] Nmap tool — port scanning, runs subprocess Nmap, parses output into findings
  - [x] Katana tool — web crawler, discovers endpoints and feeds them into attack tools
  - [x] ffuf tool — route brute-force using bundled wordlist at `scripts/wordlists/common.txt`, surfaces hidden endpoints
  - [x] Arjun tool — HTTP parameter discovery, feeds discovered params into sqlmap
  - [x] httpx tool — custom HTTP probes not covered by Nuclei; Python `urllib` fallback if binary returns no output
  - [x] Nuclei tool — misconfigs, headers, admin panels, CVEs, runs Nuclei CLI with appropriate templates
  - [x] Nikto tool — web server scan, surfaces server misconfigs and known vulnerabilities
  - [x] sqlmap tool — SQL injection detection over discovered parameterised URLs (Deep scan only)
  - [x] Hydra tool — credential brute-force against login endpoints; skipped entirely if target doesn't issue a 401 + `WWW-Authenticate: Basic` challenge (Deep scan only)
  - [x] Scan mode filter — Default runs Nmap/Katana/ffuf/httpx/Nuclei, Deep adds Arjun/Nikto/sqlmap/Hydra, Custom runs user-selected tools

- [x] Agent loop
  - [x] LangGraph `StateGraph` — `orchestrator → recon → exploit → report → finalize`
  - [x] Tool call → ArmorIQ `capture_plan` → `get_intent_token` → `invoke` flow
  - [x] Finding extraction from tool results
  - [x] Stream all §7.2 events back to backend via `broadcast` callback — backend handles all Supabase writes
  - [x] Agent halt on ArmorIQ block (`VerificationError`)

- [x] ArmorIQ integration
  - [x] Wrap every tool call with ArmorIQ validation middleware
  - [x] Handle ArmorIQ block response — halt agent, emit `intent_drift_detected` event via broadcast

- [x] Governance policy (ArmorIQ)
  - [x] Policy setup
    - [x] Define engagement scope — approved target, approved tool list per scan mode
    - [x] Configure ArmorIQ client with API key and agent ID; `ARMORIQ_MOCK=true` for local dev
  - [x] Drift classification rules
    - [x] Out-of-scope action attempted → classify as `prompt_injection`
    - [x] Valid action, wrong parameters → classify as `hallucination`
  - [ ] Demo prompt injection setup
    - [ ] Author the payload text and embed it in the demo target's page content
    - [ ] Confirm ArmorIQ intercepts, halts, and streams the incident payload correctly

---

### Kanishk — Demo Target + Integration/Rehearsal

**Scope:** Deliberately vulnerable demo web app (`demo-target/`), planted vulnerabilities, prompt injection payload, full integration verification, and demo rehearsal.

**Interfaces Published**

- HTTP routes on `demo-target` container — reachable from `server` container on the Docker Compose network. No formal contract; the requirement is that every planted vulnerability is accessible at a stable path and confirmed triggerable (see Build Tracker verification tasks below).
- Prompt injection payload embedded in demo target page content — must be discovered by the agent's crawler and trigger an ArmorIQ block.

**Interfaces Consumed**

- None — the demo target is a passive target. Agent tools reach into it; it does not call back.

**Do Not Touch:** `client/`, `server/`, `server/agent/` internals — flag any required change to the relevant owner instead of editing directly.

**Build Tracker:**

- [x] Project scaffolding
  - [x] Simple Flask app
  - [x] Add as third container in docker-compose.yml

- [x] Planted vulnerabilities
  - [x] Exposed admin panel at `/admin` with no access control
  - [x] Verbose error page leaking stack trace and file paths
  - [x] Open database port (e.g. SQLite accessible, or just an open port)
  - [x] Missing security headers (no CSP, HSTS, X-Frame-Options)
  - [x] Session cookie without Secure/HttpOnly flags
  - [x] SQL injection vulnerable endpoint

- [x] Verification — confirm each planted vulnerability is actually reachable/triggerable
  - [x] Confirm `/admin` is live and returns 200 with no auth
  - [x] Confirm a request triggers the verbose error page with visible stack trace
  - [x] Confirm the open port is reachable from the backend container
  - [x] Confirm security headers are genuinely absent (check via curl/browser devtools)
  - [x] Confirm session cookie is missing Secure/HttpOnly flags
  - [x] Confirm the SQL injection endpoint is actually exploitable by sqlmap

- [x] Prompt injection payload
  - [x] Hidden payload on one of the pages — instructs agent to exfiltrate data instead of reporting
  - [x] Confirm ArmorIQ intercepts it and the incident panel fires correctly

- [x] Consent copy — operator-facing disclaimer text
  - [x] Draft the exact text shown to the operator before they acknowledge (placeholder until finalized): *"I confirm I am authorized to test this target. I understand this scan may include active exploitation attempts (including SQL injection via sqlmap in Deep mode) and that my IP address and acknowledgment will be logged for audit purposes."*
  - [x] Finalize wording with team — what `acknowledged: true` is standing in for must be unambiguous, since Deep mode performs active exploitation, not passive scanning

- [ ] Full integration & rehearsal — run before presentation, not during it
  - [ ] Run a complete scan end-to-end against the demo target before demo day — consent → scan → live feed → report → export
  - [ ] Run the prompt injection scenario at least once before demo day — confirm ArmorIQ blocks it and the incident panel renders correctly
  - [ ] Time the full demo flow once to make sure it fits the available slot

---

## 11. Integration Checkpoints

Components must be merged to **main** (not just on a branch) at each checkpoint before the validation test is run.

### Checkpoint 1 — Frontend ↔ Backend connectivity
- **Required merged:** Backend project scaffolding (Sujat); frontend project scaffolding with `VITE_BACKEND_URL` configured (Kirti).
- **Validation:** Frontend calls a backend health or consent endpoint and receives a response.
- **Expected output:** Confirmed network path between the two services with no CORS or connection errors.

### Checkpoint 2 — Backend ↔ Agent integration
- **Required merged:** Agent scaffolding + `run_scan` exported (Parth); backend background-task trigger wired to `run_scan` (Sujat).
- **Validation:** `POST /scan` starts the agent as a background task and the agent begins executing tools.
- **Expected output:** Scan transitions to `running` status with at least one tool invocation observed in logs.

### Checkpoint 3 — ArmorIQ validation working
- **Required merged:** ArmorIQ client configured + `capture_plan` → `get_intent_token` → `invoke` wrapping on at least one tool (Parth).
- **Validation:** A tool call is validated by ArmorIQ before execution, and a deliberately out-of-scope action is blocked.
- **Expected output:** An `IntentDriftEvent` is correctly generated and the agent halts on block.

### Checkpoint 4 — End-to-end scan execution
- **Required merged:** All agent tools wired in (Parth); scan status streaming via WebSocket (Sujat); Live Scan View rendering the stream (Kirti).
- **Validation:** A full scan against the demo target runs from `POST /scan` to `scan_completed` without manual intervention.
- **Expected output:** Findings are extracted and visible in the Live Scan View in real time.

### Checkpoint 5 — Report generation and storage
- **Required merged:** Report assembly logic + `GET /report/{scanId}` + export endpoint (Sujat); Report View (Kirti).
- **Validation:** A completed scan produces a stored report retrievable via the API and renders correctly in the frontend, including PDF export.
- **Expected output:** A downloadable PDF matching the on-screen report.

### Checkpoint 6 — Full demo rehearsal
- **Required merged:** Demo target with all planted vulnerabilities and the prompt injection payload (Kanishk); full frontend flow (Kirti); full backend + agent + governance flow (Sujat, Parth).
- **Validation:** A complete run-through — consent → scan → live feed → ArmorIQ block on the injection payload → report → export — completes successfully within the demo time slot.
- **Expected output:** A timed, successful rehearsal with no manual workarounds.

### Checkpoint 7 — Demo lock
- **Required merged:** All items in the Definition of Done checklist (§13).
- **Validation:** No outstanding blocking bugs; rehearsal from Checkpoint 6 passed.
- **Expected output:** Demo lock declared — only bug fixes permitted from this point per §13.

---

## 12. Fallback Plan

Go through the §4 architecture diagram and ask: "if this component breaks or can't be finished, does the demo die?" Every yes needs a row here.

| If… fails | Fallback action | Demo impact |
| --- | --- | --- |
| LangGraph agent | Scripted scan — hardcoded tool sequence, ArmorIQ still validates each call | Demo proceeds without live LLM reasoning narration, but governance story stays intact |
| ArmorIQ SDK | Mock validation layer — logs every tool call, allows execution, demo story holds | Loses real-time blocking, but the audit trail and demo narrative still function |
| WebSockets | Polling — frontend polls `GET /scan/{id}` every 2 seconds | Live feed becomes near-real-time instead of instant; no loss of functionality |
| Nuclei | Nmap + httpx only — still surfaces port and HTTP findings | Reduced finding coverage, but scan still completes and produces a report |
| sqlmap | Skip SQL injection step, rest of scan completes normally | Deep mode loses one finding category; Default mode unaffected |
| Supabase | In-memory store — findings held in server state for demo duration | No persistence across restarts, but the live demo flow is unaffected |

---

## 13. Definition of Done & Demo Lock

**Demo-ready checklist:**
- [ ] End-to-end scan works (consent → scan → live feed → report)
- [ ] Findings are generated for the demo target's planted vulnerabilities
- [ ] ArmorIQ blocks are demonstrated against the prompt injection payload
- [ ] Report generation works (`GET /report/{scanId}`)
- [ ] Session history works (`GET /sessions`)
- [ ] PDF export works (`GET /report/{scanId}/export`)
- [ ] Demo target validated (all planted vulnerabilities confirmed reachable/triggerable per §10)
- [ ] Full rehearsal completed and timed to fit the demo slot

**Demo lock:** <!-- date and time -->

**After demo lock:**
- ✅ Bug fixes allowed
- ❌ No new features
- ❌ No architecture changes
- ❌ No contract changes

---

## 14. Change Control

- PROJECT.md is the repository source of truth.
- Architecture changes (§4) require team approval.
- Contract changes (§7) require team approval.
- Schema changes (§6 / §7.4) require team approval.
- Environment config changes (§8) require team approval.
- Ownership changes (§10) require team approval.
- Any approved change must be reflected immediately in the relevant section of this document.
- No silent edits to shared project context — if a change affects another teammate's work, that teammate must be informed before the document is updated.
- Changes to this document must follow the commit format in §9, scoped to `project` — e.g. `docs(project): update internal interface for run_scan`.
- AI assistants must not edit this document unilaterally — flag proposed changes to the tech lead.
