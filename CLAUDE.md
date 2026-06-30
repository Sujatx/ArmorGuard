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

## Architecture

- **Agent pipeline:** LangGraph `StateGraph` — `orchestrator → recon → exploit → report → finalize`
- **Governance:** ArmorIQ facade in `agent/governance/armoriq_client.py` — enforce/report/complete/delegate
- **LLM:** Groq `llama-3.3-70b-versatile` via LangChain (`agent/llm.py`)
- **Scanner tools:** baked into Docker image at `/opt/tools` (PATH precedence over Python httpx CLI)
- **Database:** Supabase (PostgREST client); scan state + findings + intent drift events
- **Frontend:** React + Vite, deployed on Vercel; WS connection to backend for live scan logs

## ArmorIQ Integration

- `ARMORIQ_AGENT_ID` and `ARMORIQ_API_KEY` set in `backend/.env`
- `ARMORIQ_MOCK=true` disables real enforcement (local deterministic backstop only)
- Policy must be created in platform.armoriq.ai scoped to the agent with `allowedTools` = the 9 scanner names and `defaultEnforcementAction = block`
- `delegate_subtree()` (SDK ≥ 0.3.9) used for sub-agent token delegation; falls back to scoped local token on 500
- All enforcement failures degrade gracefully — scans always complete

## Scanner Notes

- **nmap:** ports 80 + 443 always filtered before findings (`skip_standard_web_ports`); LLM interpretation with `classify_ports_deterministic` fallback
- **httpx:** ProjectDiscovery binary with Python `urllib` fallback for when binary returns no output
- **hydra:** skipped entirely if target doesn't issue a 401 + `WWW-Authenticate: Basic` challenge
- **ffuf wordlist:** `scripts/wordlists/common.txt`
- **nikto:** built from source in Docker image
