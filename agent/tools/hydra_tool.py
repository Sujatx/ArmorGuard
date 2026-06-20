import logging
import subprocess
import uuid
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse

from agent.config import HYDRA_PATH, HYDRA_WORDLIST

_DEFAULT_USERLIST = ["admin", "root", "user", "test", "administrator"]
_DEFAULT_PASSLIST = ["admin", "password", "123456", "root", "pass", "test", ""]


def run_hydra_scan(target_url: str, scan_id: str) -> List[Dict[str, Any]]:
    parsed = urlparse(target_url)
    host = parsed.hostname
    scheme = parsed.scheme or "http"
    port = str(parsed.port) if parsed.port else ("443" if scheme == "https" else "80")
    path = parsed.path if parsed.path else "/"

    if not host:
        return []

    # Use a bundled wordlist if available, otherwise fall back to a small inline list.
    if HYDRA_WORDLIST:
        user_arg = ["-L", HYDRA_WORDLIST]
        pass_arg = ["-P", HYDRA_WORDLIST]
    else:
        user_arg = ["-l", "admin"]
        pass_arg = ["-p", "admin"]

    service = "https-get" if scheme == "https" else "http-get"
    cmd = [
        HYDRA_PATH,
        *user_arg,
        *pass_arg,
        "-s", port,
        "-t", "4",      # 4 parallel tasks — stay polite
        "-f",            # stop after first valid credential pair
        host,
        service,
        path,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        stdout = result.stdout

        if "login:" in stdout.lower() and "password:" in stdout.lower():
            cracked_line = next(
                (ln for ln in stdout.splitlines() if "login:" in ln.lower()), stdout[:500]
            )
            return [{
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "Critical",
                "title": "Weak/Default Credentials Detected",
                "description": (
                    f"Hydra found valid credentials on {target_url}. "
                    "The service accepted a guessable username/password combination."
                ),
                "remediation": (
                    "Immediately change the default credentials. Enforce a strong password policy, "
                    "implement account lockout after failed attempts, and consider MFA."
                ),
                "evidence": cracked_line.strip()[:2000],
                "createdAt": datetime.utcnow().isoformat() + "Z",
            }]

        # No credentials found — informational, not a finding worth persisting.
        return []

    except subprocess.TimeoutExpired:
        print("[hydra_tool] WARNING: hydra timed out.")
        return []
    except FileNotFoundError:
        msg = f"[hydra_tool] '{HYDRA_PATH}' not found on PATH — hydra is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[hydra_tool] WARNING: error running hydra — {e}")
        return []
