"""JWT weakness probe (headless replacement for the Burp 'JWT Editor' extension).

Gated by the fingerprint signal ``has_jwt`` — only runs when the target actually issued
a JWT (in a Set-Cookie or an Authorization: Bearer header). Tests the classic offline
weaknesses that need no server interaction to detect:
  * ``alg:none`` acceptance surface (token forged with the signature stripped)
  * weak HMAC secret (dictionary attack against the signature)

Detection here is deterministic and offline; the Confirm phase is what actually *proves*
exploitability by replaying a forged token against a protected endpoint (see confirm.py).

We shell out to the `jwt_tool` CLI when present (ProjectDiscovery-style pip/git install),
and fall back to a self-contained pure-Python check so the tool still produces a signal
in a bare environment.
"""
import base64
import hashlib
import hmac
import json
import logging
import subprocess
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from agent.config import JWT_TOOL_PATH

# A tiny built-in secret list for the offline fallback. The Dockerfile ships jwt_tool with
# its own rockyou-style list; this is only the no-binary backstop.
_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt", "admin", "key",
    "your-256-bit-secret", "supersecret", "s3cr3t", "test", "qwerty",
]


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
        # carried through so the Confirm phase knows how to prove this one
        "findingType": "jwt",
    }


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _decode_header(token: str) -> Optional[dict]:
    try:
        header_seg = token.split(".")[0]
        return json.loads(_b64url_decode(header_seg))
    except Exception:
        return None


def _crack_hs256(token: str) -> Optional[str]:
    """Return the secret if the HS256 signature is forgeable from the built-in list."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        expected = _b64url_decode(sig_b64)
    except Exception:
        return None
    for secret in _WEAK_SECRETS:
        mac = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(mac, expected):
            return secret
    return None


def _fallback_check(token: str, scan_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    header = _decode_header(token)
    if header is None:
        return findings
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        findings.append(_finding(
            scan_id, "Critical", "JWT Accepts 'alg: none' (Unsigned Token)",
            "The application issued a JWT whose header declares alg=none, meaning tokens are "
            "unsigned. An attacker can craft arbitrary claims (e.g. elevate to admin) that the "
            "server will accept without any signature check.",
            "Reject the 'none' algorithm server-side. Pin the accepted algorithm explicitly "
            "(e.g. only HS256/RS256) and verify the signature on every request.",
            f"JWT header: {json.dumps(header)}"))

    if alg.startswith("hs"):
        secret = _crack_hs256(token)
        if secret:
            findings.append(_finding(
                scan_id, "Critical", "JWT Signed With a Weak/Guessable Secret",
                f"The JWT's HMAC signature was forged offline using the secret '{secret}'. Any "
                "attacker who guesses the secret can mint valid tokens with arbitrary claims.",
                "Rotate the signing secret to a long, random value (>= 256 bits). Store it in a "
                "secrets manager, never in source. Consider asymmetric signing (RS256).",
                f"Recovered HMAC secret: {secret!r}"))
    return findings


def run_jwt_scan(target_url: str, scan_id: str,
                 fingerprints: Optional[dict] = None) -> List[Dict[str, Any]]:
    fp = fingerprints or {}
    token = fp.get("jwt_sample") or ""
    if not token:
        print("[jwt_tool] No JWT captured during fingerprint — skipping.")
        return []

    # Prefer the jwt_tool CLI when installed; parse its plain-text verdicts.
    try:
        result = subprocess.run(
            [JWT_TOOL_PATH, token, "-M", "at"],  # -M at → run the "all tests" quick mode
            capture_output=True, text=True, timeout=60,
        )
        out = (result.stdout + result.stderr)
        low = out.lower()
        findings: List[Dict[str, Any]] = []
        if "alg:none" in low or "alg: none" in low or "unsigned" in low:
            findings.append(_finding(
                scan_id, "Critical", "JWT Accepts 'alg: none' (Unsigned Token)",
                "jwt_tool reported the endpoint accepts an unsigned (alg=none) token — an "
                "attacker can forge arbitrary claims with no signature.",
                "Reject 'none'; pin the accepted algorithm and verify signatures.",
                out[:1500]))
        if "cracked" in low or "secret" in low and "found" in low:
            findings.append(_finding(
                scan_id, "Critical", "JWT Signed With a Weak/Guessable Secret",
                "jwt_tool recovered the HMAC signing secret via dictionary attack.",
                "Rotate to a long random secret; prefer asymmetric signing (RS256).",
                out[:1500]))
        if findings:
            print(f"[jwt_tool] Completed via CLI — {len(findings)} finding(s).")
            return findings
        # CLI ran but found nothing conclusive — still try the offline check.
        return _fallback_check(token, scan_id)
    except subprocess.TimeoutExpired:
        print("[jwt_tool] jwt_tool CLI timed out — using offline check.")
        return _fallback_check(token, scan_id)
    except FileNotFoundError:
        logging.warning("[jwt_tool] '%s' not on PATH — using offline check.", JWT_TOOL_PATH)
        return _fallback_check(token, scan_id)
    except Exception as e:
        print(f"[jwt_tool] WARNING: error running jwt_tool — {e}")
        return _fallback_check(token, scan_id)
