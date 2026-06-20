import json
import logging
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from typing import Any, Dict, List

from agent.config import NIKTO_PATH

# nikto does not emit severities; bump items whose text suggests real exposure.
_MEDIUM_KEYWORDS = (
    "admin", "password", "backup", "config", "injection", "traversal",
    "disclosure", "default", "phpinfo", ".git", "shell", "upload",
)


def run_nikto_scan(target_url: str, scan_id: str) -> List[Dict[str, Any]]:
    """Run nikto against the target and map its results into findings."""
    print(f"[nikto_tool] Starting nikto scan against: {target_url}")

    tmpdir = tempfile.mkdtemp(prefix="nikto_")
    outfile = os.path.join(tmpdir, "nikto.json")
    try:
        cmd = [
            NIKTO_PATH,
            "-h", target_url,
            "-Format", "json",
            "-output", outfile,
            "-maxtime", "120",
            "-nointeractive",
            "-ask", "no",
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        if not os.path.exists(outfile):
            print("[nikto_tool] No nikto output produced.")
            return []
        with open(outfile) as fh:
            raw = fh.read().strip()
        if not raw:
            return []
        data = json.loads(raw)

        # nikto JSON is sometimes a single object, sometimes a list of host objects.
        hosts = data if isinstance(data, list) else [data]
        findings: List[Dict[str, Any]] = []
        for host in hosts:
            for vuln in (host.get("vulnerabilities", []) if isinstance(host, dict) else []):
                msg = vuln.get("msg") or vuln.get("id", "nikto finding")
                url = vuln.get("url", "")
                method = vuln.get("method", "GET")
                blob = f"{msg} {url}".lower()
                severity = "Medium" if any(k in blob for k in _MEDIUM_KEYWORDS) else "Low"
                findings.append({
                    "findingId": str(uuid.uuid4()),
                    "scanId": scan_id,
                    "severity": severity,
                    "title": f"Nikto: {msg[:90]}",
                    "description": f"nikto reported: {msg}",
                    "remediation": (
                        "Review the flagged resource. Remove or restrict exposed files, "
                        "directories, and default content, and apply server hardening."
                    ),
                    "evidence": f"{method} {url}\nnikto id: {vuln.get('id', 'n/a')}",
                    "createdAt": datetime.utcnow().isoformat() + "Z",
                })

        print(f"[nikto_tool] Completed scan. Found {len(findings)} finding(s).")
        return findings

    except subprocess.TimeoutExpired:
        print("[nikto_tool] WARNING: nikto timed out.")
        return []
    except FileNotFoundError:
        msg = f"[nikto_tool] '{NIKTO_PATH}' not found on PATH — nikto is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[nikto_tool] WARNING: Error running nikto — {e}")
        return []
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
