import json
import logging
import ssl
import subprocess
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from agent.config import HTTPX_PATH

def _python_header_check(target_url: str, scan_id: str) -> List[Dict[str, Any]]:
    """Direct Python urllib fallback for when the httpx binary produces no output.
    Makes a single GET request and runs the same security-header checks."""
    print(f"[httpx_tool] Python header probe: {target_url}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "ArmorGuard/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            raw_headers = dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw_headers = dict(e.headers)
    except Exception as exc:
        print(f"[httpx_tool] Python probe failed: {exc}")
        return []

    headers_norm = {k.lower().replace("_", "-"): v for k, v in raw_headers.items()}
    findings: List[Dict[str, Any]] = []

    checks = [
        ("content-security-policy", "Medium",
         "Missing Content-Security-Policy (CSP) Header",
         "The Content-Security-Policy (CSP) header is missing from the HTTP response. "
         "CSP helps prevent XSS, clickjacking, and code injection attacks by restricting "
         "the sources from which content can be loaded.",
         "Return a 'Content-Security-Policy' header. Baseline: "
         "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"),
        ("x-frame-options", "Medium",
         "Missing X-Frame-Options Header (Clickjacking Risk)",
         "The X-Frame-Options header is missing. Without it, malicious sites can embed "
         "this page in an iframe (clickjacking / UI redressing attacks).",
         "Return 'X-Frame-Options: DENY' or 'SAMEORIGIN'. "
         "Alternatively use the CSP 'frame-ancestors' directive."),
        ("x-content-type-options", "Low",
         "Missing X-Content-Type-Options Header",
         "The X-Content-Type-Options header is missing. Browsers may MIME-sniff "
         "response content-types, which can lead to XSS when users can upload files.",
         "Set 'X-Content-Type-Options: nosniff' on all responses."),
        ("referrer-policy", "Low",
         "Missing Referrer-Policy Header",
         "The Referrer-Policy header is missing. URL path/query parameters may leak "
         "to external domains when users navigate away.",
         "Return 'Referrer-Policy: strict-origin-when-cross-origin'."),
    ]

    for header_name, severity, title, description, remediation in checks:
        if header_name not in headers_norm:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": severity,
                "title": title,
                "description": description,
                "remediation": remediation,
                "evidence": f"Target: {target_url}\nHeader '{header_name}' not present in response.",
                "createdAt": datetime.utcnow().isoformat() + "Z",
            })

    if target_url.lower().startswith("https://") and "strict-transport-security" not in headers_norm:
        findings.append({
            "findingId": str(uuid.uuid4()),
            "scanId": scan_id,
            "severity": "Low",
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "description": "The HSTS header is missing on an HTTPS endpoint. Browsers may "
                           "allow insecure HTTP connections, exposing users to SSL stripping.",
            "remediation": "Return 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            "evidence": f"Target: {target_url}\nHeader 'strict-transport-security' not present in response.",
            "createdAt": datetime.utcnow().isoformat() + "Z",
        })

    print(f"[httpx_tool] Python probe complete — {len(findings)} issue(s) found.")
    return findings


def run_httpx_scan(
    target_url: str, 
    scan_id: str, 
    client: Optional[Any] = None, 
    intent_token: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """Runs ProjectDiscovery httpx binary against the target URL and analyzes response headers for security misconfigurations.
    Every call is validated in real-time by the ArmorIQ client before execution.
    
    Args:
        target_url: The target website URL.
        scan_id: The active scan identifier.
        client: The ArmorIQ client wrapper instance.
        intent_token: The signed intent token.
        
    Returns:
        List of findings matching the Finding shape contract.
    """
    print(f"[httpx_tool] Starting HTTPX scan against: {target_url}")
    
    # 1. Perform ArmorIQ Intent Verification before execution
    if client is not None and intent_token is not None:
        print("[httpx_tool] Verifying intent with ArmorIQ...")
        # This will raise PolicyBlockedException / IntentMismatchException if blocked/mismatched
        client.invoke(
            mcp="agent_tools",
            action="httpx",
            intent_token=intent_token,
            params={"target": target_url}
        )
        print("[httpx_tool] Intent verified successfully by ArmorIQ.")

    cmd = [
        HTTPX_PATH,
        "-u", target_url,
        "-json",
        "-irh",
        "-no-stdin",
        "-silent",
        "-timeout", "20",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()

        if not output:
            stderr_hint = result.stderr.strip()
            print(f"[httpx_tool] No output received from httpx binary "
                  f"(exit={result.returncode}, stderr={stderr_hint!r:.200}). "
                  "Falling back to Python header probe.")
            return _python_header_check(target_url, scan_id)

        # httpx -json outputs one JSON object per line; take the first valid one
        data = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

        if not data:
            print("[httpx_tool] Could not parse JSON output from httpx.")
            return []

        # Try both field names — older httpx uses "header", newer uses "response_headers"
        raw_headers = data.get("response_headers") or data.get("header") or {}
        if isinstance(raw_headers, list):
            # Some versions return a list of single-key dicts
            merged: dict = {}
            for item in raw_headers:
                if isinstance(item, dict):
                    merged.update(item)
            raw_headers = merged
        # HTTP headers are case-insensitive and httpx serializes them with underscores
        # (e.g. content_security_policy) rather than hyphens. Normalize both so lookups
        # don't miss headers that are genuinely present.
        headers_norm = {k.lower().replace("_", "-"): v for k, v in raw_headers.items()}
        
        findings = []
        
        # Check security headers
        # 1. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers_norm:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "Medium",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "description": "The Content-Security-Policy (CSP) header is missing from the HTTP response. CSP is a powerful security header that helps prevent Cross-Site Scripting (XSS), clickjacking, and code injection attacks by restricting the sources from which content can be loaded.",
                "remediation": "Configure your web server or application middleware to return a 'Content-Security-Policy' HTTP response header. Start with a secure baseline such as: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';",
                "evidence": f"Target: {target_url}\nReturned headers: {json.dumps(raw_headers, indent=2)}",
                "createdAt": datetime.utcnow().isoformat() + "Z"
            })
            
        # 2. X-Frame-Options (Clickjacking)
        if "x-frame-options" not in headers_norm:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "Medium",
                "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
                "description": "The X-Frame-Options header is missing from the HTTP response. Without this header, malicious sites can embed this page inside an iframe on their own site, leading to UI redressing / clickjacking attacks.",
                "remediation": "Configure your web server to return the 'X-Frame-Options' header with a value of 'DENY' or 'SAMEORIGIN'. Alternatively, use the CSP 'frame-ancestors' directive.",
                "evidence": f"Target: {target_url}\nReturned headers: {json.dumps(raw_headers, indent=2)}",
                "createdAt": datetime.utcnow().isoformat() + "Z"
            })
            
        # 3. X-Content-Type-Options
        if "x-content-type-options" not in headers_norm:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "Low",
                "title": "Missing X-Content-Type-Options Header",
                "description": "The X-Content-Type-Options header is missing. Browsers might attempt to MIME-sniff the response content-type (e.g. rendering text/plain files as HTML), which can result in Cross-Site Scripting (XSS) if users can upload arbitrary files.",
                "remediation": "Set the 'X-Content-Type-Options' response header to 'nosniff' for all responses.",
                "evidence": f"Target: {target_url}\nReturned headers: {json.dumps(raw_headers, indent=2)}",
                "createdAt": datetime.utcnow().isoformat() + "Z"
            })
            
        # 4. Referrer-Policy
        if "referrer-policy" not in headers_norm:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "Low",
                "title": "Missing Referrer-Policy Header",
                "description": "The Referrer-Policy header is missing. When users click links that navigate away from your site, sensitive information contained within the path/query parameters of the URL might leak to external domains.",
                "remediation": "Configure your server to send a 'Referrer-Policy' header. The recommended default is 'strict-origin-when-cross-origin'.",
                "evidence": f"Target: {target_url}\nReturned headers: {json.dumps(raw_headers, indent=2)}",
                "createdAt": datetime.utcnow().isoformat() + "Z"
            })
            
        # 5. Set-Cookie security flags
        set_cookie = headers_norm.get("set-cookie", "")
        if set_cookie:
            cookie_issues = []
            if "httponly" not in set_cookie.lower():
                cookie_issues.append("HttpOnly flag is missing — the cookie is accessible to JavaScript, making it stealable via XSS")
            if "secure" not in set_cookie.lower():
                cookie_issues.append("Secure flag is missing — the cookie will be transmitted over plain HTTP connections")
            if "samesite" not in set_cookie.lower():
                cookie_issues.append("SameSite attribute is missing — the cookie is sent on cross-site requests, increasing CSRF risk")

            import re as _re
            val_match = _re.search(r'[^;,\s]+=([^;,\s]+)', set_cookie)
            if val_match:
                val = val_match.group(1)
                if _re.search(r'(admin|test|demo|default|guest|user|session_\d)', val.lower()):
                    cookie_issues.append(f"cookie value '{val}' appears hardcoded or predictable — session tokens must be randomly generated per session")

            if cookie_issues:
                findings.append({
                    "findingId": str(uuid.uuid4()),
                    "scanId": scan_id,
                    "severity": "High",
                    "title": "Insecure Session Cookie Configuration",
                    "description": "The Set-Cookie header was found with one or more security misconfigurations: " + "; ".join(cookie_issues) + ".",
                    "remediation": "Set the HttpOnly flag to block JavaScript access. Set the Secure flag to enforce HTTPS-only transmission. Add SameSite=Strict or SameSite=Lax to prevent cross-site request forgery. Ensure session token values are cryptographically random and not derived from predictable patterns.",
                    "evidence": f"Target: {target_url}\nSet-Cookie: {set_cookie}\nReturned headers: {json.dumps(raw_headers, indent=2)}",
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                })

        # 6. Strict-Transport-Security (HSTS) - Only for HTTPS
        is_https = target_url.lower().startswith("https://")
        if is_https and "strict-transport-security" not in headers_norm:
            findings.append({
                "findingId": str(uuid.uuid4()),
                "scanId": scan_id,
                "severity": "Low",
                "title": "Missing Strict-Transport-Security (HSTS) Header",
                "description": "The Strict-Transport-Security (HSTS) header is missing on an HTTPS endpoint. Without this header, browsers may allow insecure HTTP connections to the server, exposing users to SSL stripping and man-in-the-middle (MITM) attacks.",
                "remediation": "Set the 'Strict-Transport-Security' header on your web server for all HTTPS responses. Example: max-age=31536000; includeSubDomains",
                "evidence": f"Target: {target_url}\nReturned headers: {json.dumps(raw_headers, indent=2)}",
                "createdAt": datetime.utcnow().isoformat() + "Z"
            })
            
        print(f"[httpx_tool] Completed scan. Found {len(findings)} issues.")
        return findings
        
    except subprocess.TimeoutExpired:
        print("[httpx_tool] Subprocess timeout expired — falling back to Python header probe.")
        return _python_header_check(target_url, scan_id)
    except FileNotFoundError:
        msg = f"[httpx_tool] '{HTTPX_PATH}' not found on PATH — httpx is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[httpx_tool] WARNING: Error running httpx — {e}")
        return []
