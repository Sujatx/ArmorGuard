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
HYDRA_PATH = os.environ.get("HYDRA_PATH", "hydra")
# Optional credential wordlist for hydra; leave empty to use hydra's built-in defaults.
HYDRA_WORDLIST = os.environ.get("HYDRA_WORDLIST", "")

# Intent-driven ("autonomous") roster — headless CLI tools, gated on fingerprint signals.
# jwt_tool / commix / odat expose console entrypoints (pip/git); graphql-cop is `graphql-cop`.
JWT_TOOL_PATH = os.environ.get("JWT_TOOL_PATH", "jwt_tool")
GRAPHQL_COP_PATH = os.environ.get("GRAPHQL_COP_PATH", "graphql-cop")
COMMIX_PATH = os.environ.get("COMMIX_PATH", "commix")
ODAT_PATH = os.environ.get("ODAT_PATH", "odat")

# --- Knowledge base (Select-phase RAG) ---------------------------------------------
# Local sentence-transformers model — CPU-only, no API key, baked into the image.
# 384-dim; must match the vector(384) column in knowledge_schema.sql.
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
EMBEDDING_DIM = int(os.environ.get("EMBEDDING_DIM", "384"))
# Set to "false" to disable retrieval (Select falls back to fingerprint-only selection).
KNOWLEDGE_ENABLED = os.environ.get("KNOWLEDGE_ENABLED", "true").lower() == "true"

# Wordlist for ffuf route brute-forcing. The Docker image bundles this list at
# /opt/tools/wordlists/common.txt; outside the container we fall back to the copy checked
# into the repo (scripts/wordlists/common.txt) so local dev runs aren't silently skipped.
# Override with FFUF_WORDLIST to point anywhere else.
def _default_ffuf_wordlist() -> str:
    docker_path = "/opt/tools/wordlists/common.txt"
    if os.path.exists(docker_path):
        return docker_path
    repo_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "wordlists", "common.txt")
    )
    return repo_path if os.path.exists(repo_path) else docker_path

FFUF_WORDLIST = os.environ.get("FFUF_WORDLIST") or _default_ffuf_wordlist()
