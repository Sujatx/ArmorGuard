import asyncio
import uuid as _uuid
from typing import List, Optional
from ipaddress import ip_address
from urllib.parse import urlparse

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from database import (
    insert_consent_record, get_consent_record,
    insert_scan, get_scan_with_findings, update_scan,
    get_sessions as db_get_sessions,
    insert_audit_log_event, insert_intent_drift_event,
)
from pdf_export import generate_report_pdf

try:
    from agent.agent import run_scan as _agent_run_scan
    AGENT_AVAILABLE = True
except ImportError:
    AGENT_AVAILABLE = False

app = FastAPI(
    title="ArmorGuard Backend",
    description="FastAPI service for autonomous AI pentesting agent with ArmorIQ governance",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


# --- Models ---

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
    scan_mode: str = "default"
    selected_tools: Optional[List[str]] = None
    consent_id: Optional[str] = None

class ScanResponse(CamelModel):
    scan_id: str
    status: str

class Finding(CamelModel):
    finding_id: str
    severity: str
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


# --- Helpers ---

def is_local_target(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname or parsed.path
        if not hostname:
            return True
        if hostname.lower() in ("localhost", "127.0.0.1", "demo-target"):
            return True
        ip = ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except Exception:
        h = target_url.lower()
        return any(x in h for x in ("localhost", "127.0.0.1", "demo-target", "192.168.", "10."))


def _assert_valid_uuid(scan_id: str) -> None:
    try:
        _uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan not found")


def _finding_row(row: dict) -> Finding:
    return Finding(
        finding_id=row["finding_id"],
        severity=row["severity"],
        title=row["title"],
        description=row["description"],
        remediation=row["remediation"],
        evidence=row.get("evidence"),
        created_at=row["created_at"],
    )


def _build_report(row: dict) -> ReportResponse:
    findings = [_finding_row(f) for f in row.get("findings", [])]
    by_sev = SeveritySummary()
    for f in findings:
        setattr(by_sev, f.severity, getattr(by_sev, f.severity) + 1)
    risk_score = min(100, by_sev.Critical * 40 + by_sev.High * 25 + by_sev.Medium * 10 + by_sev.Low * 2)
    return ReportResponse(
        scan_id=row["scan_id"],
        target_url=row["target_url"],
        scan_mode=row["scan_mode"],
        summary=ReportSummary(
            risk_score=risk_score,
            total_findings=len(findings),
            by_severity=by_sev,
        ),
        findings=findings,
    )


# --- REST Endpoints ---

@app.post("/consent", response_model=ConsentRecord)
def post_consent(request: Request, body: ConsentRequest):
    operator_ip = request.client.host if request.client else "127.0.0.1"
    row = insert_consent_record(body.target_url, operator_ip)
    return ConsentRecord(
        consent_id=row["consent_id"],
        target_url=row["target_url"],
        operator_ip=row["operator_ip"],
        timestamp=row["timestamp"],
        acknowledged=row["acknowledged"],
    )


@app.post("/scan", response_model=ScanResponse, responses={400: {"model": ErrorResponse}})
def post_scan(body: ScanRequest, background_tasks: BackgroundTasks):
    if not is_local_target(body.target_url):
        if not body.consent_id:
            raise HTTPException(status_code=400, detail={"error": "consent_required", "message": "Consent is required for public targets."})
        consent = get_consent_record(body.consent_id)
        if not consent or not consent["acknowledged"]:
            raise HTTPException(status_code=400, detail={"error": "consent_required", "message": "Valid consent acknowledgment not found."})
        if consent["target_url"] != body.target_url:
            raise HTTPException(status_code=400, detail={"error": "consent_required", "message": "Consent target mismatch."})

    if body.scan_mode == "custom" and not body.selected_tools:
        raise HTTPException(status_code=400, detail={"error": "tools_required", "message": "Custom scan mode requires at least one selected tool."})

    row = insert_scan(body.target_url, body.scan_mode, body.selected_tools, body.consent_id)
    if AGENT_AVAILABLE:
        background_tasks.add_task(
            _agent_run_scan,
            row["scan_id"], body.target_url, body.scan_mode, body.selected_tools or [],
        )
    return ScanResponse(scan_id=row["scan_id"], status="started")


@app.get("/scan/{scanId}", response_model=ScanStatusResponse)
def get_scan(scanId: str):
    _assert_valid_uuid(scanId)
    row = get_scan_with_findings(scanId)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatusResponse(
        scan_id=row["scan_id"],
        target_url=row["target_url"],
        scan_mode=row["scan_mode"],
        status=row["status"],
        progress=row["progress"],
        findings=[_finding_row(f) for f in row.get("findings", [])],
    )


@app.get("/report/{scanId}", response_model=ReportResponse)
def get_report(scanId: str):
    _assert_valid_uuid(scanId)
    row = get_scan_with_findings(scanId)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _build_report(row)


@app.get("/report/{scanId}/export")
def get_report_export(scanId: str):
    _assert_valid_uuid(scanId)
    row = get_scan_with_findings(scanId)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf_bytes = generate_report_pdf(_build_report(row))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="armorguard-report-{scanId}.pdf"'},
    )


@app.get("/sessions", response_model=SessionsResponse)
def get_sessions():
    rows = db_get_sessions()
    return SessionsResponse(sessions=[
        SessionItem(
            scan_id=r["scan_id"],
            target_url=r["target_url"],
            date=r["date"],
            severity_summary=SeveritySummary(**r["severity_summary"]),
        )
        for r in rows
    ])


# --- WebSocket ---

@app.websocket("/ws/scan/{scanId}")
async def websocket_scan(websocket: WebSocket, scanId: str):
    await websocket.accept()
    row = await asyncio.to_thread(get_scan_with_findings, scanId)
    if not row:
        await websocket.send_json({"event": "scan_failed", "data": {"reason": "Scan not found"}})
        await websocket.close()
        return

    async def broadcast(event: dict) -> None:
        """Callback passed to the agent — it calls this to push §7 events over the WebSocket."""
        await websocket.send_json(event)
        # Persist audit / drift events to Supabase as they arrive.
        name = event.get("event")
        data = event.get("data", {})
        if name == "tool_status":
            await asyncio.to_thread(
                insert_audit_log_event, scanId,
                "tool_call", f"{data.get('tool')} {data.get('status')}", data,
            )
        elif name == "intent_drift_detected":
            await asyncio.to_thread(
                insert_intent_drift_event, scanId,
                data.get("errorCode", ""), data.get("blockReason", ""),
                data.get("driftClassification", ""), data.get("attemptedAction", ""),
            )
        elif name == "scan_completed":
            await asyncio.to_thread(update_scan, scanId, {"status": "completed", "progress": 100})
        elif name == "scan_failed":
            await asyncio.to_thread(update_scan, scanId, {"status": "failed"})

    try:
        if AGENT_AVAILABLE:
            await _agent_run_scan(
                scanId, row["target_url"], row["scan_mode"],
                row.get("selected_tools") or [], broadcast,
            )
        else:
            # Scaffold fallback — runs until Parth's agent is merged.
            await broadcast({"event": "scan_started", "data": {"scanId": scanId}})
            await broadcast({"event": "agent_reasoning", "data": {"text": "Initializing security checks..."}})
            for tool in ("nmap", "nuclei", "httpx"):
                await broadcast({"event": "tool_status", "data": {"tool": tool, "status": "running", "message": f"Running {tool}..."}})
                await broadcast({"event": "tool_status", "data": {"tool": tool, "status": "done", "message": f"{tool} complete."}})
            await broadcast({"event": "scan_completed", "data": {"scanId": scanId}})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await broadcast({"event": "scan_failed", "data": {"reason": str(e)}})
    finally:
        await websocket.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
