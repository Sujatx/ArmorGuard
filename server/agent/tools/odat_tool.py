"""Oracle Database Attacking Tool (ODAT) runner.

Gated by the fingerprint signal ``oracle_listener`` (nmap found TCP 1521 open). ODAT
enumerates and attacks an exposed Oracle TNS listener: SID guessing, listener info leak,
and default-credential checks. In the Attack phase we run the read-only ``all`` module in
enumeration mode; nothing is written to the database.
"""
import logging
import subprocess
import uuid
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse

from agent.config import ODAT_PATH


def _finding(scan_id: str, severity: str, title: str, description: str,
             remediation: str, evidence: str) -> Dict[str, Any]:
    return {
        "findingId": str(uuid.uuid4()),
        "scanId": scan_id,
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "findingType": "oracle",
    }


def run_odat_scan(target_url: str, scan_id: str) -> List[Dict[str, Any]]:
    host = urlparse(target_url).hostname or target_url
    port = "1521"
    print(f"[odat_tool] Probing Oracle TNS listener at {host}:{port}")

    # `odat all` runs the full read-only enumeration battery against the listener.
    cmd = [ODAT_PATH, "all", "-s", host, "-p", port]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        out = result.stdout + result.stderr
        low = out.lower()
        findings: List[Dict[str, Any]] = []

        # A reachable listener that leaks version/SIDs is itself an exposure.
        if "valid sid" in low or "sid found" in low or "the sid" in low:
            findings.append(_finding(
                scan_id, "High", "Oracle TNS Listener Exposes Valid SID(s)",
                f"ODAT enumerated one or more valid Oracle SIDs on {host}:{port}. A reachable "
                "TNS listener that discloses SIDs lets an attacker target authentication and "
                "known Oracle exploits directly.",
                "Restrict network access to port 1521 to trusted hosts only. Enable listener "
                "password protection and valid-node checking; never expose the listener publicly.",
                out[:1200]))
        if "default" in low and ("credential" in low or "password" in low) and "found" in low:
            findings.append(_finding(
                scan_id, "Critical", "Oracle Default Credentials Accepted",
                f"ODAT authenticated to the Oracle instance on {host}:{port} using default "
                "credentials, granting database access.",
                "Change all default Oracle account passwords immediately and enforce a strong "
                "password policy; lock or remove unused default accounts.",
                out[:1200]))

        if not findings and ("listener" in low and ("version" in low or "reachable" in low)):
            findings.append(_finding(
                scan_id, "Medium", "Exposed Oracle TNS Listener",
                f"An Oracle TNS listener is reachable on {host}:{port} and responded to ODAT. "
                "Exposing the listener widens the attack surface even without an immediate breach.",
                "Firewall port 1521 to trusted management hosts; enable listener authentication.",
                out[:1200]))

        print(f"[odat_tool] Completed — {len(findings)} finding(s).")
        return findings
    except subprocess.TimeoutExpired:
        print("[odat_tool] WARNING: odat timed out.")
        return []
    except FileNotFoundError:
        logging.warning("[odat_tool] '%s' not on PATH — skipping.", ODAT_PATH)
        return []
    except Exception as e:
        print(f"[odat_tool] WARNING: error running odat — {e}")
        return []
