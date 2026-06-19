import os
import uuid
import datetime
from typing import List, Dict, Any, Optional
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, BackgroundTasks, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict
from pydantic.alias_generators import to_camel

# Initialize FastAPI App
app = FastAPI(
    title="ArmorGuard Backend",
    description="FastAPI scaffold for autonomous AI pentesting agent governance layer",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom Pydantic Base Configuration for CamelCase serialization/deserialization over the wire
class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True
    )

# --- Data Models (from Section 4.5 of BUILDPLAN.md) ---

class ConsentRequest(CamelModel):
    target_url: str

class ConsentRecord(CamelModel):
    consent_id: str
    target_url: str
    operator_ip: str
    timestamp: str
    acknowledged: bool

class ScanRequest(CamelModel):
    target_url: str
    scan_mode: str = "default"  # default | deep | custom
    selected_tools: Optional[List[str]] = None
    consent_id: Optional[str] = None

class ScanResponse(CamelModel):
    scan_id: str
    status: str

class Finding(CamelModel):
    finding_id: str
    severity: str  # Critical | High | Medium | Low
    title: str
    description: str
    remediation: str
    evidence: Optional[str] = None
    created_at: str

class ScanStatusResponse(CamelModel):
    scan_id: str
    target_url: str
    scan_mode: str
    status: str
    progress: int
    findings: List[Finding]

class SeveritySummary(CamelModel):
    Critical: int = 0
    High: int = 0
    Medium: int = 0
    Low: int = 0

class ReportSummary(CamelModel):
    risk_score: int
    total_findings: int
    by_severity: SeveritySummary

class ReportResponse(CamelModel):
    scan_id: str
    target_url: str
    scan_mode: str
    summary: ReportSummary
    findings: List[Finding]

class SessionItem(CamelModel):
    scan_id: str
    target_url: str
    date: str
    severity_summary: SeveritySummary

class SessionsResponse(CamelModel):
    sessions: List[SessionItem]

class ErrorResponse(CamelModel):
    error: str
    message: str

# --- In-Memory Mock Databases for Scaffold ---
consent_db: Dict[str, ConsentRecord] = {}
scans_db: Dict[str, ScanStatusResponse] = {}
audit_logs: List[Dict[str, Any]] = []
drift_events: List[Dict[str, Any]] = []

# --- Helper Functions ---

def is_local_target(target_url: str) -> bool:
    """
    Detects if the target is local/private (skips consent) vs public (requires consent).
    Checks IP address ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), 
    localhost names, and custom docker bridge name "demo-target".
    """
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname or parsed.path  # fallback if scheme omitted
        
        if not hostname:
            return True
        
        if hostname.lower() in ("localhost", "127.0.0.1", "demo-target"):
            return True
            
        # Try checking if hostname parses to an IP
        ip = ip_address(hostname)
        if ip.is_private or ip.is_loopback:
            return True
    except Exception:
        # If parsing fails, fall back to checking substrings of private ranges
        h = target_url.lower()
        if "localhost" in h or "127.0.0.1" in h or "demo-target" in h or "192.168." in h or "10." in h:
            return True
    return False

# Seed some mock data for GET /sessions and history checks
def seed_mock_data():
    mock_scan_id = "d3b07384-d113-4956-a5db-38148b3064d1"
    scans_db[mock_scan_id] = ScanStatusResponse(
        scan_id=mock_scan_id,
        target_url="http://demo-target:5000",
        scan_mode="default",
        status="completed",
        progress=100,
        findings=[
            Finding(
                finding_id=str(uuid.uuid4()),
                severity="High",
                title="Exposed Admin Panel",
                description="The administrator control panel is accessible without authentication.",
                remediation="Configure basic authentication or IP access control restriction.",
                evidence="HTTP/1.1 200 OK\nServer: Werkzeug/3.0.1 Python/3.11.0",
                created_at=datetime.datetime.utcnow().isoformat() + "Z"
            ),
            Finding(
                finding_id=str(uuid.uuid4()),
                severity="Medium",
                title="Missing Security Headers",
                description="The web server does not set recommended security headers (CSP, HSTS, X-Frame-Options).",
                remediation="Add standard OWASP security headers to responses.",
                evidence="No Content-Security-Policy header detected",
                created_at=datetime.datetime.utcnow().isoformat() + "Z"
            )
        ]
    )

seed_mock_data()

# --- API Endpoints ---

@app.post("/consent", response_model=ConsentRecord)
async def post_consent(request: Request, body: ConsentRequest):
    operator_ip = request.client.host if request.client else "127.0.0.1"
    consent_id = str(uuid.uuid4())
    record = ConsentRecord(
        consent_id=consent_id,
        target_url=body.target_url,
        operator_ip=operator_ip,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        acknowledged=True
    )
    consent_db[consent_id] = record
    return record

@app.post("/scan", response_model=ScanResponse, responses={400: {"model": ErrorResponse}})
async def post_scan(body: ScanRequest, background_tasks: BackgroundTasks):
    target_is_local = is_local_target(body.target_url)

    # 1. Consent Validation for public targets
    if not target_is_local:
        if not body.consent_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "consent_required", "message": "Consent is required for public targets."}
            )
        
        consent_record = consent_db.get(body.consent_id)
        if not consent_record or not consent_record.acknowledged:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "consent_required", "message": "Valid consent acknowledgment not found."}
            )
        
        # 2. Consent-target mismatch check
        # Verify stored targetUrl matches the scan's targetUrl
        if consent_record.target_url != body.target_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "consent_required", "message": "Consent target mismatch: Consent ID was authorized for a different URL."}
            )

    # 3. Custom mode tool validation
    if body.scan_mode == "custom":
        if not body.selected_tools or len(body.selected_tools) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "tools_required", "message": "Custom scan mode requires at least one selected tool."}
            )

    # Create scan record
    scan_id = str(uuid.uuid4())
    scans_db[scan_id] = ScanStatusResponse(
        scan_id=scan_id,
        target_url=body.target_url,
        scan_mode=body.scan_mode,
        status="running",
        progress=10,
        findings=[]
    )

    # In a real app, background_tasks would run the agent loop
    # For scaffold, we start it as 'running' status
    return ScanResponse(scan_id=scan_id, status="started")

@app.get("/scan/{scanId}", response_model=ScanStatusResponse)
async def get_scan(scanId: str):
    if scanId not in scans_db:
        raise HTTPException(status_code=404, detail="Scan session not found")
    return scans_db[scanId]

@app.get("/report/{scanId}", response_model=ReportResponse)
async def get_report(scanId: str):
    if scanId not in scans_db:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    scan = scans_db[scanId]
    
    # Calculate summary statistics
    by_severity = SeveritySummary(Critical=0, High=0, Medium=0, Low=0)
    for finding in scan.findings:
        sev = finding.severity
        if sev == "Critical":
            by_severity.Critical += 1
        elif sev == "High":
            by_severity.High += 1
        elif sev == "Medium":
            by_severity.Medium += 1
        elif sev == "Low":
            by_severity.Low += 1
            
    total = len(scan.findings)
    # Simple risk score math
    risk_score = min(100, (by_severity.Critical * 40) + (by_severity.High * 25) + (by_severity.Medium * 10) + (by_severity.Low * 2))

    return ReportResponse(
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        scan_mode=scan.scan_mode,
        summary=ReportSummary(
            risk_score=risk_score,
            total_findings=total,
            by_severity=by_severity
        ),
        findings=scan.findings
    )

@app.get("/report/{scanId}/export")
async def get_report_export(scanId: str):
    if scanId not in scans_db:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    # Generate simple PDF dummy bytes to fulfill binary PDF requirement
    # Using dynamic ReportLab import if needed, but simple fallback to PDF file structure is safer
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << >> >>\nendobj\n4 0 obj\n<< /Length 50 >>\nstream\nBT /F1 12 Tf 70 700 Td (ArmorGuard PDF Report Scaffold) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000056 00000 n \n0000000111 00000 n \n0000000212 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n311\n%%EOF"
    
    headers = {
        "Content-Disposition": f'attachment; filename="armorguard-report-{scanId}.pdf"'
    }
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)

@app.get("/sessions", response_model=SessionsResponse)
async def get_sessions():
    sessions_list = []
    for scan_id, scan in scans_db.items():
        by_severity = SeveritySummary()
        for f in scan.findings:
            if f.severity == "Critical": by_severity.Critical += 1
            elif f.severity == "High": by_severity.High += 1
            elif f.severity == "Medium": by_severity.Medium += 1
            elif f.severity == "Low": by_severity.Low += 1
            
        sessions_list.append(
            SessionItem(
                scan_id=scan.scan_id,
                target_url=scan.target_url,
                date=datetime.datetime.utcnow().isoformat() + "Z", # Stubbed date
                severity_summary=by_severity
            )
        )
    return SessionsResponse(sessions=sessions_list)

# --- WebSocket Route ---

@app.websocket("/ws/scan/{scanId}")
async def websocket_scan(websocket: WebSocket, scanId: str):
    await websocket.accept()
    if scanId not in scans_db:
        await websocket.send_json({"event": "scan_failed", "data": {"reason": "Scan ID not found"}})
        await websocket.close()
        return

    try:
        # Stream standard lifecycle events to scaffold realistic progress
        await websocket.send_json({"event": "scan_started", "data": {"scanId": scanId}})
        
        await websocket.send_json({"event": "agent_reasoning", "data": {"text": "Initializing environment and preparing security policy checks..."}})
        
        await websocket.send_json({"event": "tool_status", "data": {"tool": "nmap", "status": "running", "message": "Scanning common ports..."}})
        # Simulate quick discovery of open ports
        await websocket.send_json({"event": "tool_status", "data": {"tool": "nmap", "status": "done", "message": "Nmap completed. Ports 80, 443, 5000 found open."}})
        
        # Add finding dynamically for demonstration
        new_finding = Finding(
            finding_id=str(uuid.uuid4()),
            severity="Low",
            title="Cookie Security Flags Missing",
            description="The session cookie is missing Secure or HttpOnly flags.",
            remediation="Ensure session management cookies are defined with HTTPOnly and Secure parameters.",
            created_at=datetime.datetime.utcnow().isoformat() + "Z"
        )
        scans_db[scanId].findings.append(new_finding)
        scans_db[scanId].progress = 50
        
        await websocket.send_json({"event": "finding_discovered", "data": new_finding.model_dump(by_alias=True)})
        
        await websocket.send_json({"event": "tool_status", "data": {"tool": "nuclei", "status": "running", "message": "Running web application vulnerability scanner..."}})
        await websocket.send_json({"event": "tool_status", "data": {"tool": "nuclei", "status": "done", "message": "Nuclei scanner finished checking common CVEs."}})
        
        # Finish scan
        scans_db[scanId].status = "completed"
        scans_db[scanId].progress = 100
        await websocket.send_json({"event": "scan_completed", "data": {"scanId": scanId}})
        
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"event": "scan_failed", "data": {"reason": str(e)}})
    finally:
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
