import json
import logging
import os
import re
import subprocess
import tempfile
import urllib.request
import uuid
from datetime import datetime
from typing import Any, Dict, List

from agent.config import NIKTO_PATH

# nikto does not emit severities; bump items whose text suggests real exposure.
_MEDIUM_KEYWORDS = (
    "admin", "password", "backup", "config", "injection", "traversal",
    "disclosure", "default", "phpinfo", ".git", "shell", "upload",
)

# Headers whose values are CDN/platform routing IDs — nikto's IPv6 regex fires on
# substrings like "1::5" inside Vercel's sin1::5kbp6-... routing format.
_CDN_ROUTING_HEADERS = frozenset({
    "x-vercel-id", "x-amz-cf-id", "cf-ray", "x-cache", "x-served-by",
    "x-timer", "x-cache-hits", "x-backend-server",
})

# Headers injected only on CDN error responses (4xx/5xx). Nikto probes non-existent paths
# and the resulting findings get attributed to the main site — unconditional false positives.
_CDN_ERROR_HEADERS = frozenset({
    "x-vercel-error", "x-amzn-errortype", "x-netlify-error",
})

# Platform informational headers nikto flags as "unusual" — none carry security relevance.
_CDN_NOISE_HEADERS = frozenset({
    "x-vercel-id", "x-vercel-cache", "x-vercel-age",
    "x-amz-cf-id", "x-amz-request-id",
    "cf-cache-status", "cf-ray",
    "x-timer", "x-powered-by-plesk",
})

# CDN wildcard TLS domain suffixes — the cert is platform infrastructure and is not
# actionable by the site owner.
_CDN_WILDCARD_SUFFIXES = (
    ".vercel.app", ".netlify.app", ".github.io", ".pages.dev",
    ".cloudfront.net", ".azurewebsites.net", ".web.app",
)


def _fetch_response_headers(url: str) -> Dict[str, str]:
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return {}


def _filter_nikto_findings(findings: List[Dict], resp_headers: Dict[str, str]) -> List[Dict]:
    """Drop known nikto false positive and noise categories."""
    content_enc = resp_headers.get("content-encoding", "").lower()
    has_compression = any(enc in content_enc for enc in ("deflate", "gzip", "br", "compress"))
    allows_credentials = resp_headers.get("access-control-allow-credentials", "").lower() == "true"

    _ipv6_re = re.compile(r'[0-9a-f]{0,4}::[0-9a-f]', re.IGNORECASE)

    filtered = []
    for f in findings:
        blob = (f.get("title", "") + " " + f.get("description", "") + " " + f.get("evidence", "")).lower()

        # BREACH without actual compression in the response
        if "breach" in blob and not has_compression:
            print("[nikto_tool] Dropping BREACH finding — Content-Encoding not present")
            continue

        # IPv6 regex misfiring on CDN routing ID substrings (e.g. sin1::5kbp6-...)
        if _ipv6_re.search(blob) and any(h in blob for h in _CDN_ROUTING_HEADERS):
            print("[nikto_tool] Dropping CDN routing-ID false positive (IPv6 regex matched inside platform header)")
            continue

        # Headers that only appear on error responses — triggered by nikto probing 404 paths
        # and then incorrectly attributed to the main site
        if any(h in blob for h in _CDN_ERROR_HEADERS):
            print("[nikto_tool] Dropping error-state CDN header finding (triggered by non-existent path probe)")
            continue

        # Platform informational headers with no security relevance
        if any(h in blob for h in _CDN_NOISE_HEADERS):
            print("[nikto_tool] Dropping CDN platform header noise")
            continue

        # content-disposition: inline is a CDN default on normal page responses — not a finding
        if "content-disposition" in blob and "inline" in blob:
            print("[nikto_tool] Dropping content-disposition: inline noise (CDN default, not a vulnerability)")
            continue

        # Wildcard TLS cert for CDN-managed domains — not owned or changeable by the site owner
        if ("wildcard" in blob or "*." in blob) and any(s in blob for s in _CDN_WILDCARD_SUFFIXES):
            print("[nikto_tool] Dropping CDN wildcard TLS cert finding (platform-managed, not actionable)")
            continue

        # CORS wildcard is only a risk when the server also allows credentialed requests
        if "access-control-allow-origin" in blob and "*" in blob and not allows_credentials:
            print("[nikto_tool] Dropping CORS wildcard finding — Access-Control-Allow-Credentials not set")
            continue

        filtered.append(f)

    return filtered


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

        resp_headers = _fetch_response_headers(target_url)
        findings = _filter_nikto_findings(findings, resp_headers)
        print(f"[nikto_tool] Completed scan. Found {len(findings)} finding(s) after filtering.")
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
