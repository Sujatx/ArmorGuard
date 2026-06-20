# ArmorGuard

ArmorGuard is an autonomous AI pentesting agent designed to proactively probe target web applications for security vulnerabilities and automatically generate severity-scored forensic audit reports. Governed in real time by the ArmorIQ SDK, the agent intercepts intent drifts and prompt injections mid-task, ensuring safe and compliant execution of diagnostic and exploitation tools.

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and fill in your keys before starting anything.

```env
SUPABASE_URL=your-supabase-project-url
SUPABASE_KEY=your-supabase-service-role-key

ARMORIQ_API_KEY=ak_live_...
ARMORIQ_AGENT_ID=

# LLM provider: gemini | groq | claude | ollama
LLM_PROVIDER=groq
GEMINI_API_KEY=
GROQ_API_KEY=
CLAUDE_API_KEY=
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

| Variable | Required? | What happens if missing |
|---|---|---|
| `SUPABASE_URL` / `SUPABASE_KEY` | **Required** | Backend crashes on startup |
| `GROQ_API_KEY` (or other LLM key) | Optional | Scan completes, final summary is skipped |
| `ARMORIQ_API_KEY` | Optional | Automatically runs in mock/local mode — governance gate still fires, no real ArmorIQ server needed |

## Prerequisites

When running via Docker Compose you do **not** need to install the scanner tools — all eight
are baked into the backend image and resolve on PATH inside the container
(see `backend/Dockerfile`).

For local (non-Docker) development, run the install script once:
```powershell
.\scripts\install_tools.ps1
```

| Tool | Role |
|---|---|
| nmap | Port scan |
| katana | Endpoint crawler (discovery) |
| ffuf | Route brute-forcer (discovery) |
| arjun | Parameter discovery |
| httpx | HTTP header probe |
| nuclei | Template scan (misconfigs, CVEs) |
| nikto | Web server vulnerability scan |
| sqlmap | SQL injection test |

Every binary path is overridable via env vars (`NMAP_PATH`, `KATANA_PATH`, etc.); they default to the tool name on PATH.

## Running Locally

### Option 1: Docker Compose (Recommended)
```powershell
docker-compose up --build
```
This boots:
- **Frontend** at [http://localhost:3000](http://localhost:3000)
- **Backend** (FastAPI) at [http://localhost:8000](http://localhost:8000)
- **Demo Target** (Flask) at [http://localhost:5000](http://localhost:5000)

> **Note:** When using Docker, reach the demo target from the agent as `http://host.docker.internal:5000`, not `localhost:5000`.

### Option 2: Running Services Separately

#### Backend
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Server runs at `http://127.0.0.1:8000`.

#### Frontend
```powershell
cd frontend
npm install
npm run dev
```
Client runs at `http://localhost:3000`.

#### Demo Target
```powershell
cd demo-target
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Demo app runs at `http://127.0.0.1:5000`.

## Usage

Give ArmorGuard a target and it runs the full pipeline autonomously — consent, scan, findings, report — no manual steps.

```powershell
# Demo target (no consent needed)
.\scripts\scan.ps1 -Target http://host.docker.internal:5000

# Public target (consent handled automatically)
.\scripts\scan.ps1 -Target https://example.com

# Deep scan
.\scripts\scan.ps1 -Target https://example.com -Mode deep
```

The script handles consent for public targets, polls until the scan completes, and prints severity-ranked findings. The full JSON report is at `GET /report/{scanId}` and can be exported as PDF via `GET /report/{scanId}/export`.

### Scan Modes

| Mode | Tools | Use when |
|---|---|---|
| `default` | nmap → katana → ffuf → httpx → nuclei | Quick recon — good for demos |
| `deep` | nmap → katana → ffuf → arjun → httpx → nuclei → nikto → sqlmap | Full discovery→attack chain (~5–10 min) |
| `custom` | Your choice via `selectedTools` | Targeted testing |

### Live Event Stream (optional)

Connect a WebSocket client to watch findings arrive in real time:
```powershell
wscat -c "ws://localhost:8000/ws/scan/<scanId>"
```
Event sequence: `scan_started` → `tool_status` → `finding_discovered` → `agent_reasoning` → `scan_completed`. On ArmorIQ block: `intent_drift_detected` → `agent_halted`.

### Session History

```powershell
Invoke-RestMethod -Uri http://localhost:8000/sessions
```

---

## Architecture, Locked Contracts, and Database Schema
- The full specifications, API endpoint signatures, and database schemas are defined in [PROJECT.md](PROJECT.md) at the repository root.
- The PostgreSQL database schema definition is in PROJECT.md §7.

## Current State
- **Backend**: Fully wired to Supabase — all 6 REST routes and the WebSocket handler read/write real data. Consent flow, scan management, report assembly, PDF export (ReportLab), audit trail (`AuditLogEvent` + `IntentDriftEvent`), and session history are all live.
- **Agent**: deterministic, governed scan pipeline over a `Scanner` registry — eight tools wired (nmap, katana, ffuf, arjun, httpx, nuclei, nikto, sqlmap) with a discovery→attack data flow and an ArmorIQ gate before every tool. Runs on Groq (swappable to Gemini or Claude via `LLM_PROVIDER`) for the executive summary. Streams tool status, findings, and reasoning live over WebSocket. Adding a scanner = one registry entry.
- **Frontend**: Scaffolding initialized using Next.js 14 (App Router) + Tailwind CSS.
- **Demo Target**: A minimal Flask application listening on port 5000. Planted vulnerabilities and prompt injection payload pending.

## Team Collaboration & Git Workflow

All teammates work in this shared repository. Follow these steps to set up your environment, contribute code safely, and keep the build plan updated.

### 1. Clone the Repository
```powershell
git clone <repository-url>
cd ArmorGuard
```

### 2. Branching Strategy
Never push directly to the `main` branch. Create a feature branch named after your task or feature:
```powershell
# Ensure you are on main and up to date
git checkout main
git pull origin main

# Naming convention: <name>/<feature-short-desc> (e.g. kirti/sidebar-ui or parth/nuclei-wrapper)
git checkout -b <your-name>/<feature-name>
```

### 3. Make Changes and Commit
Make your changes locally. Follow these rules before committing:
- Do NOT modify locked API contracts in `PROJECT.md` unless agreed upon by the entire team.
- Ensure your changes follow local conventions (snake_case internally in Python backend, camelCase JSON over the wire, etc.).

Commit with clear messages:
```powershell
git add .
git commit -m "feat(backend): implement Supabase DB connection layer"
```

### 4. Push and Create a Pull Request
Push your branch to the remote repository:
```powershell
git push origin <your-name>/<feature-name>
```
Go to your Git hosting platform (GitHub/GitLab) and create a **Pull Request (PR)** against `main`. Assign another teammate for code review and verification.

### 5. Update the Project Tracker
Once your feature is merged or as you progress, update your checklist status under Section 9 of `PROJECT.md` by checking off completed tasks (`[x]`) or marking in-progress features (`[/]`).
