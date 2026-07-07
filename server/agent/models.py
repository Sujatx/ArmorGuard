from pydantic import BaseModel, Field
from typing import List, Optional

class Finding(BaseModel):
    findingId: str = Field(..., description="Unique identifier (UUID)")
    scanId: str = Field(..., description="Scan this finding belongs to")
    severity: str = Field(..., description="Enum: Critical | High | Medium | Low")
    title: str = Field(..., description="Short title")
    description: str = Field(..., description="What was found")
    remediation: str = Field(..., description="How to fix it")
    evidence: Optional[str] = Field(None, description="Supporting evidence")
    createdAt: str = Field(..., description="Timestamp (ISO8601)")


# --- Intent-driven ("autonomous") pipeline schemas ---------------------------------
# These back the Fingerprint → Select → Attack → Confirm → Report loop. They are plain
# Pydantic models (not CamelModel) because they live inside the agent process; the WS
# layer already camel-cases finding dicts on the way out.

class Fingerprint(BaseModel):
    """Structured signals the Fingerprint phase derives from lightweight probes. The
    Select phase reads these to decide which exploitation-tier tools are *eligible*, and
    each tool's eligibility predicate reads the same fields (see agent.SCANNERS)."""
    open_ports: List[dict] = Field(default_factory=list, description="[{port, service, version}]")
    server: Optional[str] = Field(None, description="Server header value, if any")
    tech: List[str] = Field(default_factory=list, description="Detected stack markers (php, laravel, express, ...)")
    headers: dict = Field(default_factory=dict, description="Normalised response headers from the base URL")
    auth_scheme: str = Field("none", description="jwt | basic | form | saml | none")
    has_jwt: bool = Field(False, description="A JWT was observed in a cookie or Authorization header")
    graphql_endpoints: List[str] = Field(default_factory=list, description="Discovered GraphQL endpoints")
    java_markers: bool = Field(False, description="ViewState / JSESSIONID / .do|.action seen — Java deserialization surface")
    oracle_listener: bool = Field(False, description="TCP 1521 open — Oracle TNS listener")
    endpoints: List[str] = Field(default_factory=list, description="All discovered URLs")
    param_urls: List[str] = Field(default_factory=list, description="Discovered URLs carrying query parameters")


class AttackStep(BaseModel):
    """One entry in the Select phase's ordered attack plan."""
    tool: str = Field(..., description="Registry tool name to run (must be in the eligible set)")
    rationale: str = Field(..., description="Why this tool fits THIS target, grounded in the retrieved playbook")
    technique_id: str = Field("", description="MITRE ATT&CK technique id, e.g. T1190")


class AttackPlan(BaseModel):
    """Structured-output wrapper so the LLM returns an ordered list under one schema."""
    steps: List[AttackStep] = Field(default_factory=list)
