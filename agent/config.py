import os
from pathlib import Path
from dotenv import load_dotenv

# Explicitly target backend/.env so this module works regardless of CWD
# (uvicorn from backend/, tests from repo root, Docker from /app — all the same path)
_dotenv_path = Path(__file__).resolve().parent.parent / "backend" / ".env"
load_dotenv(dotenv_path=_dotenv_path)

# Project Paths
ROOT_DIR = Path(__file__).resolve().parent.parent

# ArmorIQ Configuration
raw_key = os.environ.get("ARMORIQ_API_KEY", "placeholder-api-key")
if not (raw_key.startswith("ak_live_") or raw_key.startswith("ak_claw_") or raw_key.startswith("ak_test_")):
    ARMORIQ_API_KEY = f"ak_test_{raw_key}"
else:
    ARMORIQ_API_KEY = raw_key

ARMORIQ_AGENT_ID = os.environ.get("ARMORIQ_AGENT_ID", "placeholder-agent-id")

# LLM Configuration
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "gemini").lower()
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY", "")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")

# Binary Paths — all four tools resolve on PATH (baked into the backend image,
# or installed to one location by scripts/install_tools.* for local dev).
# Each is env-overridable so a dev can point at a non-PATH binary if needed.
NMAP_PATH = os.environ.get("NMAP_PATH", "nmap")
NUCLEI_PATH = os.environ.get("NUCLEI_PATH", "nuclei")
HTTPX_PATH = os.environ.get("HTTPX_PATH", "httpx")
KATANA_PATH = os.environ.get("KATANA_PATH", "katana")
FFUF_PATH = os.environ.get("FFUF_PATH", "ffuf")
NIKTO_PATH = os.environ.get("NIKTO_PATH", "nikto")
# sqlmap and arjun are installed via pip and expose console entrypoints on PATH.
SQLMAP_PATH = os.environ.get("SQLMAP_PATH", "sqlmap")
ARJUN_PATH = os.environ.get("ARJUN_PATH", "arjun")

# Wordlist for ffuf route brute-forcing. The backend image bundles this list (see
# scripts/wordlists/common.txt); override with FFUF_WORDLIST for local dev.
FFUF_WORDLIST = os.environ.get("FFUF_WORDLIST", "/opt/tools/wordlists/common.txt")
