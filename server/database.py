import os
from typing import Optional
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

_client: Optional[Client] = None


def get_db() -> Client:
    global _client
    if _client is None:
        _client = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])
    return _client


def insert_consent_record(target_url: str, operator_ip: str) -> dict:
    res = get_db().table("consent_records").insert({
        "target_url": target_url,
        "operator_ip": operator_ip,
        "acknowledged": True,
    }).execute()
    return res.data[0]


def get_consent_record(consent_id: str) -> Optional[dict]:
    res = get_db().table("consent_records").select("*").eq("consent_id", consent_id).execute()
    return res.data[0] if res.data else None


def insert_scan(target_url: str, scan_mode: str, selected_tools: Optional[list], consent_id: Optional[str]) -> dict:
    res = get_db().table("scans").insert({
        "target_url": target_url,
        "scan_mode": scan_mode,
        "selected_tools": selected_tools or [],
        "consent_id": consent_id,
        "status": "running",
    }).execute()
    return res.data[0]


def get_scan_with_findings(scan_id: str) -> Optional[dict]:
    try:
        res = get_db().table("scans").select("*, findings(*)").eq("scan_id", scan_id).execute()
        return res.data[0] if res.data else None
    except Exception:
        return None


def update_scan(scan_id: str, updates: dict) -> None:
    get_db().table("scans").update(updates).eq("scan_id", scan_id).execute()


def insert_finding(scan_id: str, severity: str, title: str, description: str,
                   remediation: str, evidence: Optional[str],
                   confirmed: bool = False, proof: Optional[str] = None,
                   attack_technique_id: Optional[str] = None) -> dict:
    res = get_db().table("findings").insert({
        "scan_id": scan_id,
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
        # Intent-driven pipeline fields; deterministic-mode callers leave the defaults.
        "confirmed": confirmed,
        "proof": proof,
        "attack_technique_id": attack_technique_id,
    }).execute()
    return res.data[0]


def get_sessions() -> list:
    res = get_db().table("scans") \
        .select("scan_id, target_url, scan_mode, created_at, status, findings(severity)") \
        .order("created_at", desc=True) \
        .execute()
    sessions = []
    for scan in (res.data or []):
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in scan.get("findings", []):
            if f["severity"] in summary:
                summary[f["severity"]] += 1
        sessions.append({
            "scan_id": scan["scan_id"],
            "target_url": scan["target_url"],
            "scan_mode": scan.get("scan_mode") or "default",
            "date": scan["created_at"],
            "status": scan.get("status") or "running",
            "severity_summary": summary,
        })
    return sessions


def insert_audit_log_event(scan_id: str, event_type: str, message: str,
                            metadata: Optional[dict] = None) -> None:
    get_db().table("audit_log_events").insert({
        "scan_id": scan_id,
        "event_type": event_type,
        "message": message,
        "metadata": metadata or {},
    }).execute()


def insert_intent_drift_event(scan_id: str, error_code: str, block_reason: str,
                               drift_classification: str, attempted_action: str) -> None:
    get_db().table("intent_drift_events").insert({
        "scan_id": scan_id,
        "error_code": error_code,
        "block_reason": block_reason,
        "drift_classification": drift_classification,
        "attempted_action": attempted_action,
    }).execute()


def get_intent_drift_event(scan_id: str) -> Optional[dict]:
    res = get_db().table("intent_drift_events") \
        .select("*") \
        .eq("scan_id", scan_id) \
        .limit(1) \
        .execute()
    return res.data[0] if res.data else None
