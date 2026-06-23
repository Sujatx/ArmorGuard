# ArmorGuard

Autonomous AI pentesting agent that probes web applications for security vulnerabilities and generates severity-scored forensic reports. Every tool call is governed in real time by the ArmorIQ SDK — if a target page prompt-injects the agent mid-task, ArmorIQ detects the intent drift and halts execution immediately.

## Quick Start

```powershell
cp backend/.env.example backend/.env   # fill in your keys (see below)
docker compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend (API) | http://localhost:8000 |
| Demo Target | http://localhost:5000 |

## Environment Variables

```env
SUPABASE_URL=your-supabase-project-url
SUPABASE_KEY=your-supabase-service-role-key

ARMORIQ_API_KEY=ak_live_...
ARMORIQ_AGENT_ID=          # leave blank → mock/local mode

LLM_PROVIDER=groq          # groq | gemini | claude | ollama
GROQ_API_KEY=
GEMINI_API_KEY=
CLAUDE_API_KEY=
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

ARMORIQ_MOCK=false         # set true to bypass the SDK entirely
```

| Variable | Required? | Effect if missing |
|---|---|---|
| `SUPABASE_URL` / `SUPABASE_KEY` | **Yes** | Backend crashes on startup |
| `GROQ_API_KEY` (or other LLM) | Optional | Scan runs; final LLM summary is skipped |
| `ARMORIQ_API_KEY` | Optional | Runs in mock mode — governance gate still fires locally |

## Scanner Tools

All nine tools are baked into the Docker image — no local installs needed when running via Compose.

| Tool | Role |
|---|---|
| nmap | Port scan |
| katana | Endpoint crawler |
| ffuf | Route brute-forcer |
| arjun | Parameter discovery |
| httpx | HTTP header probe |
| nuclei | Template scan (misconfigs, CVEs) |
| nikto | Web server vulnerability scan |
| sqlmap | SQL injection test |
| hydra | Brute-force authentication check |

For local development outside Docker, run `.\scripts\install_tools.ps1` once to install them on PATH.

## Scan Modes

| Mode | Tools run | Use when |
|---|---|---|
| `default` | nmap → katana → ffuf → httpx → nuclei | Quick demo (2–3 min) |
| `deep` | all 9 tools in discovery → attack order | Full audit (~5–10 min) |
| `custom` | your pick via `selectedTools` | Targeted testing |

## Using the UI

1. Open http://localhost:3000
2. Click **New Scan**, enter a target URL, pick a scan mode
3. Public targets get a consent gate before the scan starts
4. Watch the live terminal stream tool-by-tool output and findings in real time
5. When complete, download a PDF report from the scan detail page

The left sidebar shows all past sessions with live status dots (running / completed / failed). Toast notifications fire on the dashboard when a scan finishes or fails while you're on another page.

## API

Full REST + WebSocket. Base URL: `http://localhost:8000`

| Endpoint | Description |
|---|---|
| `POST /consent` | Record operator consent for a public target |
| `POST /scan` | Start a scan; returns `scanId` |
| `GET /scan/{scanId}` | Current status + findings |
| `GET /report/{scanId}` | Full report JSON (risk score, findings, fix prompt) |
| `GET /report/{scanId}/export` | PDF download (named `armorguard-<hostname>.pdf`) |
| `GET /sessions` | All past scans with severity summaries |
| `WS /ws/scan/{scanId}` | Live event stream |

**WebSocket events** (server → client):

```
scan_started → tool_status → finding_discovered → agent_reasoning
→ intent_drift_detected → agent_halted   (on policy block)
→ scan_completed | scan_failed
```

A reconnecting client gets a full snapshot replay (findings + drift event if it fired) so the UI is consistent after refresh.

## Architecture

```
Frontend (Vite + React + Tailwind)
  └─ WebSocket + REST
Backend (FastAPI)
  ├─ REST routes + WebSocket broadcaster
  ├─ Background scan executor
  │   └─ Agent pipeline (deterministic, ordered)
  │       ├─ ArmorIQ governance gate (verify/enforce before each tool)
  │       └─ Scanner registry (9 tools, subprocess-based)
  └─ Supabase (scans, findings, audit_log_events, intent_drift_events)
Demo Target (Flask, deliberately vulnerable)
  └─ Prompt-injection payload embedded in HTML to exercise the drift gate
```

The agent pipeline is deterministic — tools run in a fixed discovery → attack order, not LLM-orchestrated. The LLM (Groq by default) is used only for the final executive summary. Adding a new scanner = one entry in the `Scanner` registry in `agent/agent.py`.

## Demo Target

The built-in demo target at `http://demo-target:5000` (internal) / `http://localhost:5000` (host) ships with planted vulnerabilities:

- Exposed admin panel (`/admin`, no auth)
- Verbose error page leaking stack traces
- SQL-injectable endpoint
- Missing security headers (CSP, X-Frame-Options, etc.)
- Insecure session cookie
- Open MySQL port (3306)
- Prompt-injection payload in the homepage HTML — triggers `intent_drift_detected` mid-scan

Run a default scan against `http://demo-target:5000` to see the full governance flow: findings surface, then the drift gate fires when the agent reaches the report phase, halting execution and recording the incident.
