<h1 align="center">ArmorGuard</h1>

<p align="center">
  <strong>Live at <a href="https://armor-guard.vercel.app">armor-guard.vercel.app</a> — enter a target and scan now.</strong>
</p>

<p align="center">
  <img src="docs/dashboard.png" alt="ArmorGuard dashboard" width="880" />
</p>

Autonomous AI pentesting agent that probes web applications for security vulnerabilities and generates severity-scored forensic reports. It runs as a **LangGraph multi-agent pipeline** — an orchestrator mints a root ArmorIQ intent token and delegates scoped authority to three governed sub-agents (**recon → exploit → report**). Every scanner tool call is governed in real time by the ArmorIQ SDK: if the agent is steered toward an off-scope or disallowed action, ArmorIQ blocks it, the run halts, and the incident is recorded as intent drift.

## Architecture

<p align="center">
  <img src="docs/architecture.png" alt="ArmorGuard system architecture" width="880" />
</p>

The pipeline is **deterministic** — the LLM never decides which tool to run or in what order; the graph edges fix recon → exploit → report so discovery output reliably reaches the attack tools. Governance is enforced on the **external tool calls** (verify token → scope check → ArmorIQ `/iap/sdk/enforce`); the executive summary is the agent's own output and is audited but not gated, the same way an assistant still answers you when one tool call is denied. The LLM (Groq by default, via LangChain) is used for reasoning steps, not orchestration. Adding a new scanner = one entry in the `Scanner` registry in `server/agent/agent.py`.

## Deployment

| Layer | Platform |
|---|---|
| Frontend | Vercel — [armor-guard.vercel.app](https://armor-guard.vercel.app) |
| Backend + Agent | Render |
| Database | Supabase (PostgREST) |

The React client is deployed on Vercel and connects to the backend on Render over HTTPS + WebSocket. The scanning agent and all tool binaries (nmap, nuclei, sqlmap, etc.) run inside Render's Docker environment and never touch Vercel's infra.

## Quick Start

```powershell
cp server/.env.example server/.env   # fill in your keys (see below)
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
| `GROQ_API_KEY` (or other LLM) | Optional | Scan runs; the LLM-written executive summary is skipped |
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

1. Open [armor-guard.vercel.app](https://armor-guard.vercel.app) (or http://localhost:3000 locally)
2. Click **New Scan**, enter a target URL, pick a scan mode
3. Public targets get a consent gate before the scan starts
4. Watch the live terminal stream tool-by-tool output and findings in real time
5. When complete, export a PDF report from the scan detail page

The left sidebar shows all past sessions with live status dots (running / completed / failed). Toast notifications fire on the dashboard when a scan finishes or fails while you're on another page. The UI is fully responsive — scans can be monitored from mobile.

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
→ intent_drift_detected (+ agent_halted on a blocked tool call)
→ scan_completed | scan_failed
```

`tool_status.data` carries an optional `subAgent` field (`recon` / `exploit` / `report`) marking which sub-agent ran the tool. A reconnecting client gets a full snapshot replay (findings + drift event if it fired) so the UI is consistent after refresh.

## Demo Target

The built-in demo target at `http://demo-target:5000` (internal) / `http://localhost:5000` (host) ships with planted vulnerabilities:

- Exposed admin panel (`/admin`, no auth)
- Verbose error page leaking stack traces
- SQL-injectable endpoint (`/user`)
- Missing security headers (CSP, X-Frame-Options, etc.)
- Insecure session cookie (no `Secure` / `HttpOnly`)
- Open MySQL port (3306)

Run a default scan against `http://demo-target:5000` to see the full flow: the orchestrator delegates a scoped ArmorIQ token to each sub-agent, findings surface tool-by-tool, and the run finishes with an LLM executive summary. Governance fires whenever a sub-agent attempts an off-scope or disallowed tool call — ArmorIQ blocks it, `intent_drift_detected` streams, and the run halts with the incident recorded.
