import asyncio
import re
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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, HTTPException
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

# Static finding taxonomy (CVSS/CWE/OWASP/compliance). Guarded separately from the heavy
# agent import so report enrichment works even if the agent graph fails to load.
try:
    from agent.enrichment import enrich, compliance_tags
except Exception:
    def enrich(_ftype):  # type: ignore
        return {}
    def compliance_tags(_ftype):  # type: ignore
        return []

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
    # Enterprise enrichment — derived at report-build time from the finding type (static
    # taxonomy), so no extra columns are persisted. All optional; deterministic-mode
    # findings that don't map to a known type simply leave them null.
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    attack_technique_id: Optional[str] = None
    confidence: Optional[str] = None          # "Confirmed (Exploited)" | "Detected"
    business_impact: Optional[str] = None
    affected_asset: Optional[str] = None
    reproduction: Optional[str] = None
    compliance: Optional[List[str]] = None

class ScanStatusResponse(CamelModel):
    scan_id: str
    target_url: str
    scan_mode: str
    status: str
    progress: int
    findings: List[Finding]
    # Real wall-clock timestamps for the live scan timer. created_at is the scan start;
    # completed_at is null while running and set once the scan reaches a terminal state.
    created_at: Optional[str] = None
    completed_at: Optional[str] = None

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
    scan_mode: str
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


def _infer_finding_type(title: str) -> str:
    """Map a finding title to its taxonomy key (mirrors confirm._infer_type). Confirmed
    autonomous findings carry a canonical title, so this is reliable for them."""
    t = (title or "").lower()
    if "sql injection" in t:
        return "sql_injection"
    if "command injection" in t or "os command" in t:
        return "command_injection"
    # Require a weakness keyword so a generic cookie note ("Cookie jwt … httponly flag")
    # isn't mis-enriched as a JWT signature exploit.
    if ("jwt" in t or "json web token" in t) and any(
            k in t for k in ("alg", "none", "secret", "signed", "unsigned",
                             "signature", "forge", "bypass", "weak")):
        return "jwt"
    if "graphql" in t:
        return "graphql"
    if "oracle" in t:
        return "oracle"
    return "unknown"


def _extract_asset(evidence: Optional[str]) -> Optional[str]:
    """Pull the first affected URL out of the finding evidence, for the report's
    'Affected Asset' field."""
    if not evidence:
        return None
    m = re.search(r"https?://[^\s,;\]\)]+", evidence)
    return m.group(0).rstrip(".") if m else None


def _reproduction(ftype: str, asset: Optional[str]) -> Optional[str]:
    if not asset:
        return None
    if ftype == "sql_injection":
        return (f"Issue a request to {asset} with an SQL metacharacter (single quote / boolean "
                "payload) in the vulnerable parameter. Confirmed by re-executing extraction "
                "queries against the live database.")
    if ftype == "command_injection":
        return (f"Issue a request to {asset} injecting a shell metacharacter with a bounded "
                "command (e.g. ';id'); command output was captured on re-test.")
    if ftype == "jwt":
        return (f"Forge a token via the signature-verification bypass and replay it against "
                f"{asset}; the server accepted the unsigned token.")
    return f"Re-issue the assessment request against {asset} to reproduce the confirmed condition."


def _finding_row(row: dict) -> Finding:
    title = row["title"]
    ftype = _infer_finding_type(title)
    e = enrich(ftype)                       # {} when the type is unknown
    evidence = row.get("evidence")
    asset = _extract_asset(evidence)
    confirmed = bool(row.get("confirmed"))
    confidence = None
    if confirmed:
        confidence = "Confirmed (Exploited)"
    elif e:
        confidence = "Detected"
    return Finding(
        finding_id=row["finding_id"],
        severity=row["severity"],
        title=title,
        description=row["description"],
        remediation=row["remediation"],
        evidence=evidence,
        created_at=row["created_at"],
        cvss_score=e.get("cvss_score"),
        cvss_vector=e.get("cvss_vector"),
        cwe_id=e.get("cwe_id"),
        owasp_category=e.get("owasp_category"),
        attack_technique_id=row.get("attack_technique_id") or e.get("technique_id"),
        confidence=confidence,
        business_impact=e.get("business_impact"),
        affected_asset=asset,
        reproduction=_reproduction(ftype, asset) if e else None,
        compliance=(compliance_tags(ftype) or None),
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
    scan_done = row.get("status") in ("completed", "failed")
    if findings and scan_done:
        sev_order = ["Critical", "High", "Medium", "Low"]
        sorted_findings = sorted(findings, key=lambda f: sev_order.index(f.severity))
        lines = [f"Fix the following security vulnerabilities found in my application:\n"]
        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"{i}. [{f.severity}] {f.title} — {f.remediation}")
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
async def post_scan(body: ScanRequest):
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
    asyncio.create_task(
        _start_scan_background(
            row["scan_id"], row["target_url"], row["scan_mode"], row.get("selected_tools") or [],
        )
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
        created_at=row.get("created_at"),
        completed_at=row.get("completed_at"),
    )


@app.post("/scan/{scanId}/cancel", responses={404: {"model": ErrorResponse}})
async def cancel_scan(scanId: str):
    _assert_valid_uuid(scanId)
    task = _scan_tasks.get(scanId)
    if task and not task.done():
        task.cancel()
        return {"cancelled": True}
    if scanId in _active_scans:
        # Task lookup missed (shouldn't happen) — force-fail via DB directly.
        await asyncio.to_thread(update_scan, scanId, {"status": "failed"})
        await _publish(scanId, {"event": "scan_failed", "data": {"reason": "Stopped by user"}})
        return {"cancelled": True}
    raise HTTPException(status_code=404, detail={"error": "not_running", "message": "No active scan with that ID."})


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
            scan_mode=r.get("scan_mode", "default"),
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

# asyncio.Task handles for running scans — used by the cancel endpoint.
_scan_tasks: dict = {}

# Live WebSocket subscribers per scan. The background executor fans every event out to
# these queues (in addition to persisting it), so any number of viewers stream live
# without re-running the scan. Cleared when the last subscriber for a scan disconnects.
_subscribers: dict[str, set] = {}


async def _publish(scan_id: str, event: dict) -> None:
    """Fan a (already-persisted) event out to every live WS subscriber of this scan."""
    for q in list(_subscribers.get(scan_id, ())):
        q.put_nowait(event)


async def _stamp_completion(scan_id: str) -> None:
    """Record the scan's terminal wall-clock time in its own update, isolated from the
    status flip. If the `completed_at` column isn't present yet (migration 002 not applied),
    this fails harmlessly and the status change still stands — the timer just falls back to
    freezing on the client when it observes the terminal status."""
    from datetime import datetime, timezone
    try:
        await asyncio.to_thread(
            update_scan, scan_id, {"completed_at": datetime.now(timezone.utc).isoformat()},
        )
    except Exception as e:
        import logging as _logging
        _logging.warning("stamp_completion failed for scan %s: %s", scan_id, e)


async def _persist_event(scan_id: str, event: dict) -> None:
    """Durably record audit / drift / finding / status events, independent of any WS connection.

    Persistence is best-effort: a storage error (e.g. a schema constraint on one event) is
    logged but never propagated, so recording an incident can't fail the scan that produced it."""
    name = event.get("event")
    data = event.get("data", {})
    try:
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
                bool(data.get("confirmed", False)),
                data.get("proof"),
                data.get("attackTechniqueId"),
            )
        elif name == "fingerprint_complete":
            await asyncio.to_thread(update_scan, scan_id, {"fingerprints": data})
        elif name == "scan_summary":
            await asyncio.to_thread(update_scan, scan_id, {"summary": data.get("text", "")})
        elif name == "scan_completed":
            await asyncio.to_thread(update_scan, scan_id, {"status": "completed", "progress": 100})
            await _stamp_completion(scan_id)
        elif name in ("scan_failed", "agent_halted"):
            import logging as _logging
            _logging.error("Scan %s %s: %s", scan_id, name, data)
            await asyncio.to_thread(update_scan, scan_id, {"status": "failed"})
            await _stamp_completion(scan_id)
    except Exception as e:
        import logging as _logging
        _logging.warning("persist_event(%s) failed for scan %s: %s", name, scan_id, e)


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
    _scan_tasks[scan_id] = asyncio.current_task()

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
    except asyncio.CancelledError:
        await _persist_event(scan_id, {"event": "scan_failed", "data": {"reason": "Stopped by user"}})
        await asyncio.to_thread(update_scan, scan_id, {"status": "failed"})
        await _publish(scan_id, {"event": "scan_failed", "data": {"reason": "Stopped by user"}})
    except Exception as e:
        await _persist_event(scan_id, {"event": "scan_failed", "data": {"reason": str(e)}})
    finally:
        _active_scans.discard(scan_id)
        _scan_tasks.pop(scan_id, None)


async def _replay_snapshot(send, row: dict) -> None:
    """Stream the stored state of a scan to a (re)connecting client without re-running
    the agent — used for completed/failed scans and for a second viewer of a live scan."""
    scan_id = row["scan_id"]
    await send({"event": "scan_started", "data": {"scanId": scan_id}})
    for f in row.get("findings", []):
        await send({"event": "finding_discovered", "data": _finding_event(f)})
    if row.get("summary"):
        await send({"event": "agent_reasoning", "data": {"text": row["summary"]}})
    status = row["status"]
    # A scan can carry a drift incident whether it halted (failed) or completed with the
    # report-phase summary blocked — replay it in both cases so the incident persists.
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
    if status == "completed":
        await send({"event": "scan_completed", "data": {"scanId": scan_id}})
    elif status == "failed":
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
        try:
            await websocket.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
