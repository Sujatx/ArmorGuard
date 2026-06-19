# ArmorGuard — Build Plan

---

## 1\. Project Overview

ArmorGuard is an autonomous AI pentesting agent built for vibe coders — people who ship AI-built applications without proper security audits. It actively probes a target for real vulnerabilities and generates a severity-scored forensic report automatically. Every tool call the agent makes is validated in real time by the ArmorIQ SDK — if a malicious page prompt-injects the agent mid-task, ArmorIQ detects the intent drift and halts execution immediately.

Built for NeuroX 2026 (HackBriven), June 21st, CDS Campus, Masters' Union, Gurugram. Must-use sponsor track — ArmorIQ is the required SDK.

---

## 2\. Tech Stack

| Component | Technology |
| :---- | :---- |
| Frontend | Next.js 14 (App Router) \+ Tailwind \+ shadcn/ui \+ Recharts \+ React Flow |
| Backend \+ Agent | FastAPI \+ PydanticAI (single Python service) |
| Governance | ArmorIQ SDK (manually wrapped around every PydanticAI tool call) |
| Real-time | Native FastAPI WebSockets |
| Database | Supabase (PostgreSQL) |
| Tools | Nmap (port scanning), Nuclei (admin panels, headers, misconfigs, error pages, CVEs), sqlmap (SQL injection), httpx (custom probes) |
| LLM Provider | Groq or Gemini (free tier) for build/testing phase → switch to Claude (Pro/API) for finals demo |
| Dev Start | Docker Compose — single `docker-compose up` boots frontend \+ backend containers. **Unresolved:** backend assumed to need privileged mode for Nmap raw socket access — NOT YET TESTED whether non-privileged `-sT` (TCP connect scan) covers the planted vulnerabilities adequately. Test this before build day; if `-sT` is sufficient, drop privileged mode entirely. |

---

## 3\. Architecture

**Component Flow:** Frontend → FastAPI → PydanticAI Agent → ArmorIQ → Tools → Findings → Supabase → Frontend

**Step by step:**

1. User enters target \+ selects scan mode (Default / Deep / Custom) on frontend  
2. Frontend detects target type — local skips consent, public triggers consent gate  
3. Consent acknowledged → POST `/consent` → FastAPI stores ConsentRecord  
4. POST `/scan` with target \+ scan mode \+ selected tools → FastAPI creates Scan record in Supabase  
5. FastAPI triggers PydanticAI agent as a background task, opens WebSocket to frontend  
6. Agent runs tools based on scan mode — every tool call wrapped with ArmorIQ `capture_plan` → `get_intent_token` → `invoke`  
7. LLM reasoning \+ tool call status streams via WebSocket → frontend terminal window updates live  
8. If ArmorIQ detects intent drift → agent halts, drift event streamed to frontend as alert  
9. Agent finishes → FastAPI assembles report, stores in Supabase, sends final assessment to frontend

**Scan Modes:**

- Default — Nmap \+ Nuclei \+ httpx (common vibe coder misconfigs)  
- Deep — everything in Default \+ sqlmap \+ aggressive Nuclei templates  
- Custom — user selects individual tools from checklist

**Services:**

- Frontend (Next.js) — dashboard, terminal window, scan controls, report view  
- Backend (FastAPI \+ PydanticAI) — API routes, agent loop, ArmorIQ integration, WebSocket server, Supabase connection

---

## 4\. Tasks & Subtasks

---

### 4.1 Frontend

- [ ] Project scaffolding  
        
      \- \[ \] Init Next.js 14 with App Router    
        
      \- \[ \] Configure Tailwind \\+ shadcn/ui    
        
      \- \[ \] Set up native WebSocket client    
        
      \- \[ \] Connect to backend base URL via env variable  
        
- [ ] Dashboard  
        
      \- \[ \] Layout    
        
                
        
            \- \[ \] Navbar    
        
                  \- \[ \] Logo    
        
                  \- \[ \] Hamburger menu — slides open session history sidebar    
        
            \- \[ \] Session history sidebar    
        
                  \- \[ \] List of past scans (target, date, severity summary)    
        
                  \- \[ \] Click session → opens its report view    
        
            \- \[ \] Mini terminal window    
        
                  \- \[ \] Floating, minimizable    
        
                  \- \[ \] Shows current tool running and its live logs    
        
                  \- \[ \] Updates via WebSocket in real time  
        
              
        
      \- \[ \] Home / Input view    
        
                
        
            \- \[ \] Target URL input field    
        
            \- \[ \] Auto-detect local vs public target    
        
            \- \[ \] Scan mode selector — Default / Deep / Custom    
        
            \- \[ \] Tool checklist (visible only in Custom mode)    
        
            \- \[ \] Consent gate — appears for public targets, blocks scan start until acknowledged    
        
            \- \[ \] Start scan button  
        
              
        
      \- \[ \] Live Scan view    
        
                
        
            \- \[ \] Active mission status panel (target, scan mode, current status)    
        
            \- \[ \] LLM reasoning display — streams agent thinking in real time    
        
            \- \[ \] Per-tool status messages (e.g. "Nmap scan done, starting Nuclei now")    
        
            \- \[ \] Incident panel — slides in inline on ArmorIQ block, shows attempted action, error\\\_code, block reason, drift classification  
        
              
        
      \- \[ \] Report view    
        
                
        
            \- \[ \] Severity-scored findings list (Critical / High / Medium / Low)    
        
            \- \[ \] Per-finding detail (root cause \\+ remediation)    
        
            \- \[ \] Executive risk summary    
        
            \- \[ \] Interactive vulnerability map — React Flow, nodes color-coded by severity, click node opens full finding detail    
        
            \- \[ \] Export to PDF

---

### 4.2 Backend

- [ ] Project scaffolding  
        
      \- \[ \] Init FastAPI project    
        
      \- \[ \] Configure native WebSocket server    
        
      \- \[ \] Connect to Supabase    
        
      \- \[ \] Set up env config (.env \\+ dotenv)    
        
      \- \[ \] Write Dockerfile (install Nmap, Nuclei, sqlmap, httpx inside container)    
        
      \- \[ \] Write docker-compose.yml (frontend \\+ backend, backend in privileged mode)  
        
- [ ] Consent flow  
        
      \- \[ \] Target type detection (local IP range vs public URL)    
        
      \- \[ \] \`POST /consent\` endpoint — stores ConsentRecord (target URL, operator IP, timestamp, acknowledgment)    
        
      \- \[ \] Consent validation middleware — blocks \`/scan\` for public targets without a valid ConsentRecord  
        
- [ ] Scan management  
        
      \- \[ \] \`POST /scan\` endpoint — validates consent, creates Scan record, triggers agent    
        
      \- \[ \] \`GET /scan/{id}\` endpoint — returns current scan status and findings    
        
      \- \[ \] Scan status updates via WebSocket (stream findings \\+ LLM reasoning as they arrive from agent)  
        
- [ ] Report  
        
      \- \[ \] Report assembly logic (aggregate findings, compute severity summary)    
        
      \- \[ \] Stream final report to frontend via WebSocket on scan completion    
        
      \- \[ \] \`GET /report/{scan\_id}\` endpoint — for session history, returns stored report from Supabase  
        
- [ ] Session history  
        
      \- \[ \] \`GET /sessions\` endpoint — returns list of past scans (target, date, severity summary)  
        
- [ ] Audit trail  
        
      \- \[ \] Store AuditLogEvent on every agent tool call    
        
      \- \[ \] Store IntentDriftEvent on every ArmorIQ block  
        
- [ ] PDF export  
        
      \- \[ \] \`GET /report/{scan\_id}/export\` endpoint — generates and returns PDF of full report    
        
      \- \[ \] Use WeasyPrint or ReportLab to generate PDF server-side from findings JSON  
        
- [ ] Agent integration  
        
      \- \[ \] Run PydanticAI agent as FastAPI background task (no separate service)    
        
      \- \[ \] Pass scan mode \\+ selected tools \\+ target into agent on scan start    
        
      \- \[ \] Agent streams findings \\+ reasoning back to WebSocket handler in real time

---

### 4.3 Agent

- [ ] Project scaffolding  
        
      \- \[ \] Install PydanticAI \\+ dependencies    
        
      \- \[ \] Install ArmorIQ SDK    
        
      \- \[ \] Configure ArmorIQ client (API key, agent ID)    
        
      \- \[ \] Configure LLM provider via env variable — Groq/Gemini for build phase, swappable to Claude for finals (PydanticAI model string should not be hardcoded)  
        
- [ ] Tool definitions (each tool wrapped with ArmorIQ capture\_plan → get\_intent\_token → invoke)  
        
      \- \[ \] Nmap tool — port scanning, runs subprocess Nmap, parses output into findings    
        
      \- \[ \] Nuclei tool — misconfigs, headers, admin panels, CVEs, runs Nuclei CLI with appropriate templates    
        
      \- \[ \] sqlmap tool — SQL injection detection (Deep scan only)    
        
      \- \[ \] httpx tool — custom HTTP probes not covered by Nuclei    
        
      \- \[ \] Scan mode filter — Default runs Nmap \\+ Nuclei \\+ httpx, Deep adds sqlmap \\+ aggressive Nuclei templates, Custom runs user-selected tools  
        
- [ ] Agent loop  
        
      \- \[ \] PydanticAI agent definition with all tools registered    
        
      \- \[ \] Tool call → ArmorIQ capture\\\_plan → get\\\_intent\\\_token → invoke flow    
        
      \- \[ \] Finding extraction from tool results    
        
      \- \[ \] Stream findings \\+ LLM reasoning back to WebSocket handler in real time    
        
      \- \[ \] Agent halt on ArmorIQ block (VerificationError)  
        
- [ ] ArmorIQ integration  
        
      \- \[ \] Wrap every tool call with ArmorIQ validation middleware    
        
      \- \[ \] Handle ArmorIQ block response — halt agent, emit IntentDriftEvent

---

### 4.4 Governance (ArmorIQ — runs inside backend service)

ArmorIQ SDK is initialized inside the FastAPI+PydanticAI service. All tasks here are part of the agent section build — this section defines the governance rules and policy setup only.

- [ ] Policy setup  
        
      \- \[ \] Define engagement scope — approved target, approved tool list per scan mode    
        
      \- \[ \] Configure ArmorIQ client with API key and agent ID  
        
- [ ] Drift classification rules  
        
      \- \[ \] Out-of-scope action attempted → classify as prompt injection    
        
      \- \[ \] Valid action, wrong parameters → classify as hallucination/drift    
        
      \- \[ \] Document rules so frontend incident panel labels correctly  
        
- [ ] Demo prompt injection setup  
      \- \[ \] Author the payload text and embed it in the demo target's page content  
      \- \[ \] Confirm ArmorIQ intercepts, halts, and streams incident payload correctly

---

### 4.5 API Contracts

These contracts are considered locked for the build. Any change requires flagging to the whole team before implementation, since frontend and backend will be built in parallel against these shapes.

**POST /consent**

Request:

{

  "targetUrl": "string"

}

Note: `operatorIp` is NOT sent by the client. Backend reads it server-side from the incoming request (`request.client.host` in FastAPI) so the audit trail can't be spoofed by a client lying in its own request body.

Response:

{

  "consentId": "string",

  "targetUrl": "string",

  "operatorIp": "string",

  "timestamp": "ISO8601 string",

  "acknowledged": true

}

---

**POST /scan**

Request:

{

  "targetUrl": "string",

  "scanMode": "default | deep | custom",

  "selectedTools": \["nmap", "nuclei", "sqlmap", "httpx"\],

  "consentId": "string | null"

}

- `scanMode` is optional — backend defaults to `"default"` if omitted.  
- `selectedTools` only required/used when `scanMode` is `"custom"`. If `"custom"` is selected and `selectedTools` is empty or missing, reject with 400 (`error: "tools_required"`).  
- `consentId` is required if target is public (backend validates it exists and `acknowledged: true`). Local/private-IP targets can omit it entirely.  
- Backend MUST also verify that the `targetUrl` stored on the referenced `ConsentRecord` matches the `targetUrl` in this request — a `consentId` issued for one target must not authorize a scan against a different target. Mismatch → reject with the same `consent_required` error below.

Response:

{

  "scanId": "string",

  "status": "started"

}

Error response (public target, missing or invalid consent):

{

  "error": "consent\_required",

  "message": "string"

}

---

**GET /scan/{scanId}**

Single source of truth for scan state — used for initial load, page refresh/resume, and as the WebSocket fallback (polling). Findings are included inline rather than split into a separate endpoint, so this one response works for both the polling fallback and viewing a completed scan.

Response:

{

  "scanId": "string",

  "targetUrl": "string",

  "scanMode": "default | deep | custom",

  "status": "running | completed | failed",

  "progress": 0,

  "findings": \[

    {

      "findingId": "string",

      "severity": "Critical | High | Medium | Low",

      "title": "string",

      "description": "string",

      "remediation": "string",

      "evidence": "string",

      "createdAt": "ISO8601 string"

    }

  \]

}

`severity` is a fixed enum — `Critical | High | Medium | Low` only, no free-text values. This keeps frontend severity badges and sorting deterministic.

---

**GET /report/{scanId}**

Response:

{

  "scanId": "string",

  "targetUrl": "string",

  "scanMode": "default | deep | custom",

  "summary": {

    "riskScore": 0,

    "totalFindings": 0,

    "bySeverity": {

      "Critical": 0,

      "High": 0,

      "Medium": 0,

      "Low": 0

    }

  },

  "findings": \[\]

}

`findings` uses the same finding shape as `GET /scan/{scanId}`.

---

**GET /report/{scanId}/export**

Returns a binary PDF stream, not JSON. `Content-Type: application/pdf`, with a `Content-Disposition` header suggesting filename `armorguard-report-{scanId}.pdf`.

---

**GET /sessions**

Response:

{

  "sessions": \[

    {

      "scanId": "string",

      "targetUrl": "string",

      "date": "ISO8601 string",

      "severitySummary": {

        "Critical": 0,

        "High": 0,

        "Medium": 0,

        "Low": 0

      }

    }

  \]

}

---

**WebSocket — /ws/scan/{scanId}**

Server → client events only (no client → server messages needed beyond the initial connection).

{ "event": "scan\_started", "data": { "scanId": "string" } }

{ "event": "agent\_reasoning", "data": { "text": "string" } }

{ "event": "tool\_status", "data": { "tool": "string", "status": "running | done", "message": "string" } }

{ "event": "finding\_discovered", "data": { /\* same finding shape as GET /scan/{scanId} \*/ } }

{ "event": "intent\_drift\_detected", "data": {

    "errorCode": "string",

    "blockReason": "string",

    "driftClassification": "prompt\_injection | hallucination",

    "attemptedAction": "string"

} }

{ "event": "agent\_halted", "data": { "reason": "string" } }

{ "event": "scan\_completed", "data": { "scanId": "string" } }

{ "event": "scan\_failed", "data": { "reason": "string" } }

`driftClassification` mirrors the two categories defined in section 4.4 (Drift classification rules) — out-of-scope action \= `prompt_injection`, valid action with wrong parameters \= `hallucination`. Keep this in sync if those rules change.

---

**Data Models Referenced**

These objects are defined once here; all endpoints above reference this shape rather than redefining fields inline.

- **ConsentRecord**: `consentId`, `targetUrl`, `operatorIp`, `timestamp`, `acknowledged`  
- **Scan**: `scanId`, `targetUrl`, `scanMode`, `status`, `progress`, `createdAt`  
- **Finding**: `findingId`, `scanId`, `severity` (enum), `title`, `description`, `remediation`, `evidence`, `createdAt`  
- **Report**: `scanId`, `targetUrl`, `scanMode`, `summary` (riskScore \+ bySeverity breakdown), `findings`  
- **AuditLogEvent**: `id`, `scanId`, `eventType`, `message`, `metadata`, `createdAt`  
- **IntentDriftEvent**: `id`, `scanId`, `errorCode`, `blockReason`, `driftClassification`, `attemptedAction`, `createdAt`

---

**Database Schema (Supabase / PostgreSQL)**

`Report` has no dedicated table — it is computed at read time by aggregating `scans` \+ `findings` (riskScore and `bySeverity` are derived, not stored). Everything else below maps directly to the data models above.

CREATE TABLE consent\_records (

  consent\_id     UUID PRIMARY KEY DEFAULT gen\_random\_uuid(),

  target\_url     TEXT NOT NULL,

  operator\_ip    TEXT NOT NULL,

  timestamp      TIMESTAMPTZ NOT NULL DEFAULT now(),

  acknowledged   BOOLEAN NOT NULL DEFAULT false

);

CREATE TABLE scans (

  scan\_id        UUID PRIMARY KEY DEFAULT gen\_random\_uuid(),

  target\_url     TEXT NOT NULL,

  scan\_mode      TEXT NOT NULL CHECK (scan\_mode IN ('default', 'deep', 'custom')),

  selected\_tools TEXT\[\],

  status         TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')) DEFAULT 'running',

  progress       INTEGER NOT NULL DEFAULT 0,

  consent\_id     UUID REFERENCES consent\_records(consent\_id),

  created\_at     TIMESTAMPTZ NOT NULL DEFAULT now()

);

CREATE TABLE findings (

  finding\_id     UUID PRIMARY KEY DEFAULT gen\_random\_uuid(),

  scan\_id        UUID NOT NULL REFERENCES scans(scan\_id) ON DELETE CASCADE,

  severity       TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),

  title          TEXT NOT NULL,

  description    TEXT NOT NULL,

  remediation    TEXT NOT NULL,

  evidence       TEXT,

  created\_at     TIMESTAMPTZ NOT NULL DEFAULT now()

);

CREATE TABLE audit\_log\_events (

  id             UUID PRIMARY KEY DEFAULT gen\_random\_uuid(),

  scan\_id        UUID NOT NULL REFERENCES scans(scan\_id) ON DELETE CASCADE,

  event\_type     TEXT NOT NULL,

  message        TEXT NOT NULL,

  metadata       JSONB,

  created\_at     TIMESTAMPTZ NOT NULL DEFAULT now()

);

CREATE TABLE intent\_drift\_events (

  id                   UUID PRIMARY KEY DEFAULT gen\_random\_uuid(),

  scan\_id              UUID NOT NULL REFERENCES scans(scan\_id) ON DELETE CASCADE,

  error\_code           TEXT NOT NULL,

  block\_reason         TEXT NOT NULL,

  drift\_classification TEXT NOT NULL CHECK (drift\_classification IN ('prompt\_injection', 'hallucination')),

  attempted\_action     TEXT NOT NULL,

  created\_at           TIMESTAMPTZ NOT NULL DEFAULT now()

);

\-- Indexes for the lookups the API actually does

CREATE INDEX idx\_findings\_scan\_id ON findings(scan\_id);

CREATE INDEX idx\_audit\_log\_scan\_id ON audit\_log\_events(scan\_id);

CREATE INDEX idx\_drift\_events\_scan\_id ON intent\_drift\_events(scan\_id);

CREATE INDEX idx\_scans\_created\_at ON scans(created\_at DESC); \-- for GET /sessions ordering

Notes:

- `scans.consent_id` is nullable — local/private-IP targets never create a ConsentRecord, so this stays `NULL` for those scans.  
- `riskScore` and `bySeverity` in the `GET /report/{scanId}` response are computed with a `GROUP BY severity` query over `findings`, not stored as columns.  
- `GET /sessions` reads `scans` joined with a `findings` aggregate for the severity summary — no separate sessions table needed.

---

## 5\. Demo Target

A deliberately vulnerable web app running as a third Docker container. Purpose: give ArmorGuard a controlled target with planted vulnerabilities and a prompt injection payload for the demo.

- [ ] Project scaffolding  
        
      \- \[ \] Simple Flask or Express app    
        
      \- \[ \] Add as third container in docker-compose.yml  
        
- [ ] Planted vulnerabilities  
        
      \- \[ \] Exposed admin panel at \`/admin\` with no access control    
        
      \- \[ \] Verbose error page leaking stack trace and file paths    
        
      \- \[ \] Open database port (e.g. SQLite accessible, or just an open port)    
        
      \- \[ \] Missing security headers (no CSP, HSTS, X-Frame-Options)    
        
      \- \[ \] Session cookie without Secure/HttpOnly flags    
        
      \- \[ \] SQL injection vulnerable endpoint  
        
- [ ] Verification — confirm each planted vulnerability is actually reachable/triggerable  
        
      \- \[ \] Confirm \`/admin\` is live and returns 200 with no auth    
        
      \- \[ \] Confirm a request triggers the verbose error page with visible stack trace    
        
      \- \[ \] Confirm the open port is reachable from the backend container    
        
      \- \[ \] Confirm security headers are genuinely absent (check via curl/browser devtools)    
        
      \- \[ \] Confirm session cookie is missing Secure/HttpOnly flags    
        
      \- \[ \] Confirm the SQL injection endpoint is actually exploitable by sqlmap  
        
- [ ] Prompt injection payload  
        
      \- \[ \] Hidden payload on one of the pages — instructs agent to exfiltrate data instead of reporting    
        
      \- \[ \] Confirm ArmorIQ intercepts it and incident panel fires correctly  
        
- [ ] Consent copy — operator-facing disclaimer text  
        
      \- \[ \] Draft the exact text shown to the operator before they acknowledge (placeholder until finalized): \*"I confirm I am authorized to test this target. I understand this scan may include active exploitation attempts (including SQL injection via sqlmap in Deep mode) and that my IP address and acknowledgment will be logged for audit purposes."\*    
        
      \- \[ \] Finalize wording with team — what \`acknowledged: true\` is standing in for must be unambiguous, since Deep mode performs active exploitation, not passive scanning  
        
- [ ] Full rehearsal — run before presentation, not during it  
        
      \- \[ \] Run a complete scan end-to-end against the demo target before demo day — consent → scan → live feed → report → export    
        
      \- \[ \] Run the prompt injection scenario at least once before demo day — confirm ArmorIQ blocks it and the incident panel renders correctly    
        
      \- \[ \] Time the full demo flow once to make sure it fits the available slot

---

## 6\. Fallbacks

| Component | Fallback |
| :---- | :---- |
| PydanticAI agent fails | Scripted scan — hardcoded tool sequence, ArmorIQ still validates each call |
| ArmorIQ integration fails | Mock validation layer — logs every tool call, allows execution, demo story holds |
| WebSocket fails | Polling — frontend polls `GET /scan/{id}` every 2 seconds |
| Nuclei fails | Nmap \+ httpx only — still surfaces port and HTTP findings |
| sqlmap fails | Skip SQL injection step, rest of scan completes normally |
| Supabase unreachable | In-memory store — findings held in server state for demo duration |

