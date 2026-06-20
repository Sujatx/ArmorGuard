import asyncio
import sys
import uuid as _uuid
from pathlib import Path
from typing import List, Optional
from ipaddress import ip_address
from urllib.parse import urlparse

# Add repo root to sys.path so `from agent.agent import run_scan` resolves whether
# uvicorn is launched from backend/ (local dev) or from /app (Docker).
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from database import (
    insert_consent_record, get_consent_record,
    insert_scan, get_scan_with_findings, update_scan,
    get_sessions as db_get_sessions,
    insert_audit_log_event, insert_intent_drift_event,
    insert_finding,
)
from pdf_export import generate_report_pdf

try:
    from agent.agent import run_scan as _agent_run_scan
    AGENT_AVAILABLE = True
except Exception as _agent_import_err:
    import logging as _logging
    _logging.error("Agent import failed — running scaffold fallback: %s", _agent_import_err, exc_info=True)
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
        if hostname.lower() in ("localhost", "127.0.0.1", "demo-target", "host.docker.internal"):
            return True
        ip = ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except Exception:
        h = target_url.lower()
        return any(x in h for x in ("localhost", "127.0.0.1", "demo-target", "host.docker.internal", "192.168.", "10."))


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


def _finding_event(row: dict) -> dict:
    """Convert a stored (snake_case) finding row into the camelCase shape the
    `finding_discovered` WebSocket event uses, so replayed findings match live ones."""
    return {
        "findingId": row["finding_id"],
        "scanId": row.get("scan_id"),
        "severity": row["severity"],
        "title": row["title"],
        "description": row["description"],
        "remediation": row["remediation"],
        "evidence": row.get("evidence"),
        "createdAt": row["created_at"],
    }


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
async def post_scan(body: ScanRequest, background_tasks: BackgroundTasks):
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
    background_tasks.add_task(
        _start_scan_background,
        row["scan_id"], row["target_url"], row["scan_mode"], row.get("selected_tools") or [],
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

# Scans currently executing in this process. Guards against a reconnect or a second
# browser tab kicking off a duplicate agent run (which would duplicate findings).
_active_scans: set = set()


async def _persist_event(scan_id: str, event: dict) -> None:
    """Durably record audit / drift / finding / status events, independent of any WS connection."""
    name = event.get("event")
    data = event.get("data", {})
    if name == "tool_status":
        await asyncio.to_thread(
            insert_audit_log_event, scan_id,
            "tool_call", f"{data.get('tool')} {data.get('status')}", data,
        )
    elif name == "intent_drift_detected":
        await asyncio.to_thread(
            insert_intent_drift_event, scan_id,
            data.get("errorCode", ""), data.get("blockReason", ""),
            data.get("driftClassification", ""), data.get("attemptedAction", ""),
        )
    elif name == "finding_discovered":
        await asyncio.to_thread(
            insert_finding, scan_id,
            data.get("severity"), data.get("title"),
            data.get("description"), data.get("remediation"),
            data.get("evidence"),
        )
    elif name == "scan_completed":
        await asyncio.to_thread(update_scan, scan_id, {"status": "completed", "progress": 100})
    elif name in ("scan_failed", "agent_halted"):
        await asyncio.to_thread(update_scan, scan_id, {"status": "failed"})


async def _start_scan_background(scan_id: str, target_url: str, scan_mode: str, selected_tools: list) -> None:
    """Run the agent pipeline as a background task so the scan executes even when no WS
    client is connected. Uses DB-only broadcast (persist without send).

    The _active_scans guard is atomic on the event loop (no await between check and add),
    so if a WS client connects first it claims the scan and this task skips. If WS connects
    while this task is running, the WS gets a snapshot replay from DB — not a live stream,
    but findings are all persisted and visible via GET /scan/{scanId}."""
    if scan_id in _active_scans:
        return
    _active_scans.add(scan_id)
    try:
        async def db_broadcast(event: dict) -> None:
            await _persist_event(scan_id, event)

        if AGENT_AVAILABLE:
            await _agent_run_scan(scan_id, target_url, scan_mode, selected_tools, db_broadcast)
        else:
            await db_broadcast({"event": "scan_started", "data": {"scanId": scan_id}})
            await db_broadcast({"event": "agent_reasoning", "data": {"text": "Initializing security checks..."}})
            for tool in ("nmap", "nuclei", "httpx"):
                await db_broadcast({"event": "tool_status", "data": {"tool": tool, "status": "running", "message": f"Running {tool}..."}})
                await db_broadcast({"event": "tool_status", "data": {"tool": tool, "status": "done", "message": f"{tool} complete."}})
            await db_broadcast({"event": "scan_completed", "data": {"scanId": scan_id}})
    except Exception as e:
        await _persist_event(scan_id, {"event": "scan_failed", "data": {"reason": str(e)}})
    finally:
        _active_scans.discard(scan_id)


async def _replay_snapshot(send, row: dict) -> None:
    """Stream the stored state of a scan to a (re)connecting client without re-running
    the agent — used for completed/failed scans and for a second viewer of a live scan."""
    scan_id = row["scan_id"]
    await send({"event": "scan_started", "data": {"scanId": scan_id}})
    for f in row.get("findings", []):
        await send({"event": "finding_discovered", "data": _finding_event(f)})
    status = row["status"]
    if status == "completed":
        await send({"event": "scan_completed", "data": {"scanId": scan_id}})
    elif status == "failed":
        await send({"event": "scan_failed", "data": {"reason": "Scan previously failed"}})
    # status == "running" (already in flight elsewhere): snapshot only, no terminal event.


@app.websocket("/ws/scan/{scanId}")
async def websocket_scan(websocket: WebSocket, scanId: str):
    await websocket.accept()
    row = await asyncio.to_thread(get_scan_with_findings, scanId)
    if not row:
        try:
            await websocket.send_json({"event": "scan_failed", "data": {"reason": "Scan not found"}})
        except Exception:
            pass
        await websocket.close()
        return

    async def send(event: dict) -> None:
        """Best-effort push to this client. A dead socket must never abort the scan,
        so all send errors are swallowed — persistence (below) is the source of truth."""
        try:
            await websocket.send_json(event)
        except Exception:
            pass

    async def persist(event: dict) -> None:
        await _persist_event(scanId, event)

    async def broadcast(event: dict) -> None:
        """Callback passed to the agent. Persist first (durable), then stream best-effort."""
        await persist(event)
        await send(event)

    # Run-once guard: only execute the agent if this scan is still pending and not
    # already running in this process. Check-and-add has no await between them, so it
    # is atomic on the event loop. Otherwise replay the stored snapshot (read, not re-run).
    if scanId in _active_scans or row["status"] != "running":
        await _replay_snapshot(send, row)
        await websocket.close()
        return

    _active_scans.add(scanId)
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
        _active_scans.discard(scanId)
        await websocket.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
