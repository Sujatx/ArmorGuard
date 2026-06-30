import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from agent.config import SQLMAP_PATH


def run_sqlmap_scan(
    target_url: str,
    scan_id: str,
    client: Optional[Any] = None,
    intent_token: Optional[Any] = None,
    param_urls: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    # Prefer the parameterised URLs discovered by katana — those are the real injection
    # candidates. Fall back to the classic /search?q= probe only when discovery found
    # no parameters at all, so the tool still does something against a bare target.
    if param_urls:
        targets = list(dict.fromkeys(param_urls))[:8]  # cap to bound runtime
    else:
        targets = [urljoin(target_url.rstrip("/") + "/", "search?q=test")]

    print(f"[sqlmap_tool] Testing {len(targets)} parameterised URL(s) for SQL injection")

    tmpdir = tempfile.mkdtemp(prefix="sqlmap_")
    targets_file = os.path.join(tmpdir, "targets.txt")
    try:
        with open(targets_file, "w") as fh:
            fh.write("\n".join(targets))

        cmd = [
            SQLMAP_PATH,
            "-m", targets_file,   # test every discovered parameterised URL
            "--batch",
            "--level=1",
            "--risk=1",
            "--forms",
            "--output-dir", tmpdir,
            "--timeout=20",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = (result.stdout + result.stderr).lower()
        tested = "; ".join(targets)

        findings: List[Dict[str, Any]] = []

        if "is vulnerable" in output or "injection point" in output or "sqlmap identified" in output:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "Critical",
                "title": "SQL Injection Vulnerability Confirmed",
                "description": (
                    "sqlmap confirmed a SQL injection vulnerability on one of the tested "
                    "parameterised endpoints. An attacker can manipulate database queries "
                    "to extract, modify, or delete data."
                ),
                "remediation": (
                    "Use parameterised queries or prepared statements for all database interactions. "
                    "Never concatenate user input directly into SQL strings. "
                    "Apply input validation and a WAF layer as defence-in-depth."
                ),
                "evidence": f"Tested URLs: {tested}\nVerdict: SQL injection confirmed.\n{result.stdout[:800]}",
                "createdAt": datetime.utcnow().isoformat() + "Z",
            })
        elif "might be injectable" in output or "parameter appears to be" in output:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "High",
                "title": "Potential SQL Injection Parameter Detected",
                "description": (
                    "sqlmap flagged a parameter on one of the tested endpoints as potentially "
                    "injectable. Further manual testing is recommended to confirm exploitability."
                ),
                "remediation": (
                    "Review all user-supplied inputs used in database queries. "
                    "Switch to parameterised queries or an ORM to eliminate injection risk."
                ),
                "evidence": f"Tested URLs: {tested}\nVerdict: Parameter flagged as potentially injectable.\n{result.stdout[:800]}",
                "createdAt": datetime.utcnow().isoformat() + "Z",
            })

        print(f"[sqlmap_tool] Completed scan. Found {len(findings)} finding(s).")
        return findings

    except subprocess.TimeoutExpired:
        print("[sqlmap_tool] WARNING: sqlmap subprocess timed out.")
        return []
    except FileNotFoundError:
        msg = f"[sqlmap_tool] '{SQLMAP_PATH}' not found on PATH — sqlmap is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[sqlmap_tool] WARNING: Error running sqlmap — {e}")
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
