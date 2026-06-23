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
    insert_audit_log_event, insert_intent_drift_event, get_intent_drift_event,
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
    fix_prompt: Optional[str] = None

class SessionItem(CamelModel):
    scan_id: str
    target_url: str
    date: str
    status: str
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

    fix_prompt = None
    if findings:
        sev_order = ["Critical", "High", "Medium", "Low"]
        sorted_findings = sorted(findings, key=lambda f: sev_order.index(f.severity))
        lines = [f"Fix the following security vulnerabilities found in my application:\n"]
        for i, f in enumerate(sorted_findings, 1):
            rem_short = f.remediation.split(".")[0] + "." if "." in f.remediation else f.remediation[:100]
            lines.append(f"{i}. [{f.severity}] {f.title} — {rem_short}")
        lines.append("\nFor each item: locate the relevant code, implement the fix, and output a brief summary of what was changed.")
        fix_prompt = "\n".join(lines)

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
        fix_prompt=fix_prompt,
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


def _pdf_filename(target_url: str) -> str:
    try:
        hostname = urlparse(target_url).hostname or "scan"
        safe = hostname.replace(".", "-").replace("_", "-")
        return f"armorguard-{safe}.pdf"
    except Exception:
        return "armorguard-report.pdf"


@app.get("/report/{scanId}/export")
def get_report_export(scanId: str):
    _assert_valid_uuid(scanId)
    row = get_scan_with_findings(scanId)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    drift = get_intent_drift_event(scanId)
    pdf_bytes = generate_report_pdf(_build_report(row), drift_event=drift)
    filename = _pdf_filename(row["target_url"])
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/sessions", response_model=SessionsResponse)
def get_sessions():
    rows = db_get_sessions()
    return SessionsResponse(sessions=[
        SessionItem(
            scan_id=r["scan_id"],
            target_url=r["target_url"],
            date=r["date"],
            status=r.get("status", "running"),
            severity_summary=SeveritySummary(**r["severity_summary"]),
        )
        for r in rows
    ])


# --- WebSocket ---

# Scans currently executing in this process. Guards against a reconnect or a second
# browser tab kicking off a duplicate agent run (which would duplicate findings).
_active_scans: set = set()

# Live WebSocket subscribers per scan. The background executor fans every event out to
# these queues (in addition to persisting it), so any number of viewers stream live
# without re-running the scan. Cleared when the last subscriber for a scan disconnects.
_subscribers: dict[str, set] = {}


async def _publish(scan_id: str, event: dict) -> None:
    """Fan a (already-persisted) event out to every live WS subscriber of this scan."""
    for q in list(_subscribers.get(scan_id, ())):
        q.put_nowait(event)


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
        import logging as _logging
        _logging.error("Scan %s %s: %s", scan_id, name, data)
        await asyncio.to_thread(update_scan, scan_id, {"status": "failed"})


async def _start_scan_background(scan_id: str, target_url: str, scan_mode: str, selected_tools: list) -> None:
    """Sole executor of the agent pipeline, run as a background task so the scan proceeds
    regardless of whether any WS client is connected. Each event is persisted (durable)
    and then published to live WS subscribers, so viewers get a real-time stream without
    re-running anything.

    The _active_scans guard is atomic on the event loop (no await between check and add),
    so a duplicate trigger (e.g. retried request) is a no-op."""
    if scan_id in _active_scans:
        return
    _active_scans.add(scan_id)

    # Drive a live progress bar: each finished tool advances progress by 1/total.
    # Capped below 100 so only scan_completed (which sets 100) closes it out.
    try:
        from agent.governance.policies import get_tools_for_mode
        total_tools = len(get_tools_for_mode(scan_mode, selected_tools))
    except Exception:
        total_tools = len(selected_tools) if scan_mode == "custom" else 3
    total_tools = max(total_tools, 1)
    done_tools = 0

    try:
        async def db_broadcast(event: dict) -> None:
            nonlocal done_tools
            await _persist_event(scan_id, event)
            if event.get("event") == "tool_status" and event.get("data", {}).get("status") == "done":
                done_tools += 1
                progress = min(95, round(done_tools / total_tools * 100))
                await asyncio.to_thread(update_scan, scan_id, {"progress": progress})
            await _publish(scan_id, event)

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
        drift = await asyncio.to_thread(get_intent_drift_event, scan_id)
        if drift:
            await send({
                "event": "intent_drift_detected",
                "data": {
                    "errorCode": drift["error_code"],
                    "blockReason": drift["block_reason"],
                    "driftClassification": drift["drift_classification"],
                    "attemptedAction": drift["attempted_action"],
                },
            })
        reason = drift["block_reason"] if drift else "Scan previously failed"
        await send({"event": "scan_failed", "data": {"reason": reason}})
    # status == "running" (already in flight elsewhere): snapshot only, no terminal event.


@app.websocket("/ws/scan/{scanId}")
async def websocket_scan(websocket: WebSocket, scanId: str):
    """Pure subscriber. The scan itself runs in `_start_scan_background`; this endpoint
    only replays what's already stored and then streams live events as the executor
    publishes them. Multiple viewers and reconnects are safe — none of them re-run the
    agent, and a disconnect never affects the scan."""
    import logging as _logging
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
        """Best-effort push to this client; a dead socket must never raise."""
        try:
            await websocket.send_json(event)
        except Exception:
            pass

    # Subscribe BEFORE reading the snapshot so no event published during replay is lost.
    queue: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(scanId, set()).add(queue)
    try:
        # Replay everything persisted so far (findings + terminal state for a late joiner).
        await _replay_snapshot(send, row)

        # Already finished: the snapshot delivered the terminal event, nothing to stream.
        if row["status"] != "running":
            return

        # Stream live events from the background executor until the scan ends. The timeout
        # is a safety net: if the executor died without emitting a terminal event, we
        # reconcile from the DB so the client never hangs on "running" forever.
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=20)
            except asyncio.TimeoutError:
                cur = await asyncio.to_thread(get_scan_with_findings, scanId)
                if cur and cur["status"] != "running":
                    if cur["status"] == "completed":
                        await send({"event": "scan_completed", "data": {"scanId": scanId}})
                    else:
                        await send({"event": "scan_failed", "data": {"reason": "Scan failed"}})
                    break
                continue
            await send(event)
            if event.get("event") in ("scan_completed", "scan_failed", "agent_halted"):
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        # Never let an unexpected error in the stream loop be swallowed silently.
        _logging.error("WS %s: handler raised", scanId, exc_info=True)
    finally:
        subs = _subscribers.get(scanId)
        if subs is not None:
            subs.discard(queue)
            if not subs:
                _subscribers.pop(scanId, None)
        await websocket.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
