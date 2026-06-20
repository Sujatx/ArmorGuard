import json
import logging
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from agent.config import NUCLEI_PATH

_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
}


def run_nuclei_scan(
    targets: Union[str, List[str]],
    scan_id: str,
    client: Optional[Any] = None,
    intent_token: Optional[Any] = None,
    aggressive: bool = False,
) -> List[Dict[str, Any]]:
    # Accept either a single URL or a list of discovered endpoints (from katana).
    target_list = [targets] if isinstance(targets, str) else list(dict.fromkeys(targets))
    if not target_list:
        return []
    print(f"[nuclei_tool] Starting Nuclei scan against {len(target_list)} target(s) "
          f"(aggressive={aggressive})")

    tags = "misconfig,default-login,exposure,headers"
    if aggressive:
        tags += ",cve"

    # One target → -u; many discovered endpoints → -list <tempfile> so nuclei tests
    # every route katana found, not just the base URL.
    list_file = None
    if len(target_list) == 1:
        cmd = [NUCLEI_PATH, "-u", target_list[0], "-json", "-silent", "-tags", tags]
    else:
        fd, list_file = tempfile.mkstemp(prefix="nuclei_targets_", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(target_list))
        cmd = [NUCLEI_PATH, "-list", list_file, "-json", "-silent", "-tags", tags]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout.strip()

        if not output:
            print("[nuclei_tool] No findings from Nuclei.")
            return []

        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = obj.get("info", {})
            raw_severity = info.get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(raw_severity, "Low")

            name = info.get("name", obj.get("template-id", "Unknown Finding"))
            description = info.get("description", f"Nuclei detected: {name}")
            remediation = info.get("remediation") or "Review the flagged configuration and apply security hardening."
            matched_at = obj.get("matched-at", target_list[0])
            extracted = obj.get("extracted-results") or []
            evidence = f"Template: {obj.get('template-id', 'unknown')}\nMatched at: {matched_at}"
            if extracted:
                evidence += f"\nExtracted: {'; '.join(str(x) for x in extracted[:3])}"

            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": severity,
                "title": name,
                "description": description,
                "remediation": remediation,
                "evidence": evidence,
                "createdAt": datetime.utcnow().isoformat() + "Z",
            })

        print(f"[nuclei_tool] Completed scan. Found {len(findings)} finding(s).")
        return findings

    except subprocess.TimeoutExpired:
        print("[nuclei_tool] WARNING: Nuclei subprocess timed out.")
        return []
    except FileNotFoundError:
        msg = f"[nuclei_tool] '{NUCLEI_PATH}' not found on PATH — nuclei is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[nuclei_tool] WARNING: Error running nuclei — {e}")
        return []
    finally:
        if list_file:
            try:
                os.remove(list_file)
            except OSError:
                pass
