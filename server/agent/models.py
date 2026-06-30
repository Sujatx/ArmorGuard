from pydantic import BaseModel, Field
from typing import Optional

class Finding(BaseModel):
    findingId: str = Field(..., description="Unique identifier (UUID)")
    scanId: str = Field(..., description="Scan this finding belongs to")
    severity: str = Field(..., description="Enum: Critical | High | Medium | Low")
    title: str = Field(..., description="Short title")
    description: str = Field(..., description="What was found")
    remediation: str = Field(..., description="How to fix it")
    evidence: Optional[str] = Field(None, description="Supporting evidence")
    createdAt: str = Field(..., description="Timestamp (ISO8601)")
