"""OS command-injection testing via commix.

Gated by discovered parameters (like sqlmap). commix automates detection AND exploitation
of command-injection flaws in request parameters. In the Attack phase we run detection
only (``--batch`` with a low level); the Confirm phase re-runs with a bounded read-only
command (``id`` / ``whoami``) to prove code execution — see confirm.py.
"""
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from agent.config import COMMIX_PATH


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
        "findingType": "command_injection",
    }


def run_commix_scan(target_url: str, scan_id: str,
                    param_urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    # Real injection candidates are parameterised URLs discovered by katana/arjun.
    if param_urls:
        targets = list(dict.fromkeys(param_urls))[:6]  # cap to bound runtime
    else:
        targets = [urljoin(target_url.rstrip("/") + "/", "?cmd=test")]

    print(f"[commix_tool] Testing {len(targets)} URL(s) for command injection")
    tmpdir = tempfile.mkdtemp(prefix="commix_")
    findings: List[Dict[str, Any]] = []
    try:
        for url in targets:
            cmd = [
                COMMIX_PATH,
                "-u", url,
                "--batch",
                "--level", "1",
                # Server stdin is /dev/null (not a TTY); without this, commix parses stdin
                # as a target list and never tests -u, so no candidate is ever produced.
                "--ignore-stdin",
                "--output-dir", tmpdir,
                "--timeout", "15",
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=150,
                                        stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                print(f"[commix_tool] timeout on {url}")
                continue
            except FileNotFoundError:
                logging.warning("[commix_tool] '%s' not on PATH — skipping.", COMMIX_PATH)
                return []
            out = (result.stdout + result.stderr).lower()
            if "is vulnerable" in out or "injection point" in out or "was found to be" in out:
                findings.append(_finding(
                    scan_id, "Critical", "OS Command Injection Confirmed",
                    f"commix identified a command-injection point in {url}. An attacker can run "
                    "arbitrary operating-system commands on the server, leading to full compromise.",
                    "Never pass user input to a shell. Use parameterised process APIs "
                    "(e.g. execve with an argument array), strict allow-list validation, and drop "
                    "OS-command execution from request handlers entirely where possible.",
                    f"Tested URL: {url}\n{result.stdout[:800]}"))
        print(f"[commix_tool] Completed — {len(findings)} finding(s).")
        return findings
    except Exception as e:
        print(f"[commix_tool] WARNING: error running commix — {e}")
        return findings
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
