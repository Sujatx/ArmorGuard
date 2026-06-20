# ArmorGuard

ArmorGuard is an autonomous AI pentesting agent designed to proactively probe target web applications for security vulnerabilities and automatically generate severity-scored forensic audit reports. Governed in real time by the ArmorIQ SDK, the agent intercepts intent drifts and prompt injections mid-task, ensuring safe and compliant execution of diagnostic and exploitation tools.

## Prerequisites

When running via Docker Compose you do **not** need to install anything — all eight
scanner tools are baked into the backend image and resolve on PATH inside the container
(see `backend/Dockerfile`).

For local (non-Docker) development, one script installs the tools to a single location
and writes their paths into `backend/.env`:
```powershell
# Windows
.\infrastructure\install_tools.ps1
```
```bash
# Linux / macOS
bash infrastructure/install_tools.sh
```

| Tool | Role | How it's installed |
|---|---|---|
| nmap | port scan | apt / brew / winget (system package) |
| katana | endpoint crawler (discovery) | pinned ProjectDiscovery release binary on PATH |
| ffuf | route brute-forcer (discovery) | pinned GitHub release binary on PATH |
| arjun | parameter discovery | `pip install arjun` — console entrypoint on PATH |
| httpx (ProjectDiscovery) | HTTP header probe | pinned ProjectDiscovery release binary on PATH |
| nuclei | template scan (misconfig/CVE) | pinned ProjectDiscovery release binary on PATH |
| nikto | web-server scanner | from source (sullo/nikto) in the image |
| sqlmap | SQL injection | `pip install sqlmap` — console entrypoint on PATH |

ffuf uses a bundled wordlist (`infrastructure/wordlists/common.txt`). Every binary path
is overridable via env vars (`NMAP_PATH`, `KATANA_PATH`, `FFUF_PATH`, `ARJUN_PATH`,
`HTTPX_PATH`, `NUCLEI_PATH`, `NIKTO_PATH`, `SQLMAP_PATH`, `FFUF_WORDLIST`); they default
to the PATH name of each tool.

## Running Locally

You can run the entire system using either Docker Compose or via individual service commands.

### Option 1: Docker Compose (Recommended)
From the root directory, execute:
```bash
docker-compose up --build
```
This boots:
- **Frontend** at [http://localhost:3000](http://localhost:3000)
- **Backend** (FastAPI) at [http://localhost:8000](http://localhost:8000)
- **Demo Target** (Flask) at [http://localhost:5000](http://localhost:5000)

### Option 2: Running Services Separately

#### 1. Backend
```bash
cd backend
python -m venv venv
# Activate virtual environment
# Windows:
venv\Scripts\activate
# Unix:
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload
```
Server runs at `http://127.0.0.1:8000`.

#### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
Client runs at `http://localhost:3000`.

#### 3. Demo Target
```bash
cd demo-target
python -m venv venv
# Activate virtual environment
# Windows:
venv\Scripts\activate
# Unix:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```
Demo app runs at `http://127.0.0.1:5000`.

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and fill in your keys:

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

## Usage

### Running a Scan

> **Note:** For targets running on your local machine while using Docker, use `host.docker.internal` instead of `localhost` so the agent container can reach the host network.

#### 1. Get consent (required for public/non-local targets)
```bash
curl -X POST http://localhost:8000/consent \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "http://host.docker.internal:5000"}'
```
Response includes a `consentId`.

#### 2. Start a scan
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://host.docker.internal:5000",
    "scanMode": "default",
    "selectedTools": [],
    "consentId": "<consentId from step 1>"
  }'
```
Scan modes:
- `default` — `nmap → katana → ffuf → httpx → nuclei` (recon, discovery, light attack)
- `deep` — `nmap → katana → ffuf → arjun → httpx → nuclei → nikto → sqlmap` (full discovery→attack chain, aggressive Nuclei templates)
- `custom` — pick any of the above tools via `selectedTools`

**How a scan runs:** tools execute as a **deterministic, ordered pipeline** (not LLM-orchestrated), each gated by ArmorIQ. Discovery tools (katana crawl, ffuf route brute-force) map the attack surface into a shared scan context; arjun then finds parameters on those routes; the attack tools (nuclei, nikto, sqlmap) consume that surface so they hit real endpoints instead of just the base URL. The Groq LLM writes the final executive summary (`agent_reasoning`) from the results.

Response includes a `scanId`.

#### 3. Watch live events over WebSocket
```bash
wscat -c ws://localhost:8000/ws/scan/<scanId>
```
Or connect from any WebSocket client. Events stream in real time:
- `scan_started` → `tool_status` (running/done per tool) → `finding_discovered` (one per finding) → `agent_reasoning` (Groq summary) → `scan_completed`
- On ArmorIQ block: `intent_drift_detected` → `agent_halted`

#### 4. Get the report
```bash
# JSON report
curl http://localhost:8000/report/<scanId>

# PDF export
curl http://localhost:8000/report/<scanId>/export -o report.pdf
```

#### 5. View session history
```bash
curl http://localhost:8000/sessions
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
```bash
git clone <repository-url>
cd ArmorGuard
```

### 2. Branching Strategy
Never push directly to the `main` branch. Create a feature branch named after your task or feature:
```bash
# Ensure you are on main and up to date
git checkout main
git pull origin main

# Create and switch to your feature branch
# Naming convention: <name>/<feature-short-desc> (e.g. kirti/sidebar-ui or parth/nuclei-wrapper)
git checkout -b <your-name>/<feature-name>
```

### 3. Make Changes and Commit
Make your changes locally. Follow these rules before committing:
- Do NOT modify locked API contracts in `PROJECT.md` unless agreed upon by the entire team.
- Ensure your changes follow local conventions (snake_case internally in Python backend, camelCase JSON over the wire, etc.).

Commit with clear messages:
```bash
git add .
git commit -m "feat(backend): implement Supabase DB connection layer"
```

### 4. Push and Create a Pull Request
Push your branch to the remote repository:
```bash
git push origin <your-name>/<feature-name>
```
Go to your Git hosting platform (GitHub/GitLab) and create a **Pull Request (PR)** against `main`. Assign another teammate for code review and verification.

### 5. Update the Project Tracker
Once your feature is merged or as you progress, update your checklist status under Section 9 of `PROJECT.md` by checking off completed tasks (`[x]`) or marking in-progress features (`[/]`).
