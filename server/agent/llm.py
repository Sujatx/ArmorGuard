"""LangChain chat-model factory for ArmorGuard.

Kept in its own module (rather than inside agent.py) so leaf tools — e.g. the nmap
interpreter — can pull the model without importing the graph and creating a cycle.
The provider is selected by ``LLM_PROVIDER``; the model is built lazily and cached so
the .env is fully loaded by the backend process before the client is constructed.
"""
from typing import List, Optional

from pydantic import BaseModel, Field

from agent.config import (
    LLM_PROVIDER,
    GEMINI_API_KEY, GROQ_API_KEY, CLAUDE_API_KEY,
    OLLAMA_BASE_URL, OLLAMA_MODEL,
)


def _key(val: str) -> Optional[str]:
    """Treat placeholder/empty keys as unset so the provider SDK falls back to its
    own env-var lookup instead of authenticating with a bogus value."""
    return val if (val and "placeholder" not in val) else None


def _build_model():
    if LLM_PROVIDER == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(model="llama-3.3-70b-versatile", api_key=_key(GROQ_API_KEY), temperature=0)
    elif LLM_PROVIDER in ("anthropic", "claude"):
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model="claude-sonnet-4-6", api_key=_key(CLAUDE_API_KEY), temperature=0)
    elif LLM_PROVIDER == "ollama":
        # Ollama exposes an OpenAI-compatible endpoint; reuse the OpenAI client.
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=OLLAMA_MODEL,
            base_url=f"{OLLAMA_BASE_URL}/v1",
            api_key="ollama",
            temperature=0,
        )
    else:  # gemini (default)
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model="gemini-2.0-flash", api_key=_key(GEMINI_API_KEY), temperature=0)


_model = None


def get_model():
    """Return the process-wide chat model, building it once on first use."""
    global _model
    if _model is None:
        _model = _build_model()
    return _model


# --- Structured-output schema for the nmap interpreter -----------------------------
# The LLM only classifies the security meaning of an open port; the agent fills in the
# bookkeeping fields (findingId / scanId / createdAt / evidence) afterwards, so they are
# deliberately absent here.

class PortAssessment(BaseModel):
    port: int = Field(..., description="The open TCP port number")
    severity: str = Field(..., description="Exactly one of: Critical | High | Medium | Low")
    title: str = Field(..., description="Short finding title, e.g. 'Exposed Database Service (mysql)'")
    description: str = Field(..., description="What was found and why it matters, in context of the detected service/version")
    remediation: str = Field(..., description="Concrete remediation; avoid prescriptive 'shut it down' advice for intentionally-exposed app ports")


class NmapFindings(BaseModel):
    """Wrapper so the model returns a list under a single structured-output schema."""
    findings: List[PortAssessment] = Field(default_factory=list)
