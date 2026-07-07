"""GraphQL security audit (headless replacement for the Burp 'InQL' extension).

Gated by the fingerprint signal ``graphql_endpoints`` — only runs when a GraphQL endpoint
was actually discovered. Wraps the `graphql-cop` CLI, which checks a GraphQL server for
the common misconfigurations (introspection enabled, field suggestions / info leak,
batching-based DoS, GET-based CSRF, alias overloading). Falls back to a direct
introspection probe when the binary is absent.
"""
import json
import logging
import ssl
import subprocess
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from agent.config import GRAPHQL_COP_PATH

_INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'


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
        "findingType": "graphql",
    }


# graphql-cop severity words → our enum
_SEV_MAP = {"high": "High", "medium": "Medium", "low": "Low", "info": "Low"}


def _run_cli(endpoint: str, scan_id: str) -> Optional[List[Dict[str, Any]]]:
    try:
        result = subprocess.run(
            [GRAPHQL_COP_PATH, "-t", endpoint, "-o", "json"],
            capture_output=True, text=True, timeout=60,
        )
        out = result.stdout.strip()
        if not out:
            return None
        data = json.loads(out)
        # graphql-cop emits a list of {title, severity, description, ...}
        items = data if isinstance(data, list) else data.get("results", [])
        findings: List[Dict[str, Any]] = []
        for item in items:
            sev = _SEV_MAP.get(str(item.get("severity", "low")).lower(), "Low")
            title = item.get("title", "GraphQL Misconfiguration")
            findings.append(_finding(
                scan_id, sev, f"GraphQL: {title}",
                item.get("description", f"graphql-cop flagged '{title}' on {endpoint}."),
                item.get("remediation",
                         "Disable introspection and field suggestions in production, cap query "
                         "depth/complexity, and rate-limit the GraphQL endpoint."),
                f"Endpoint: {endpoint}\n{json.dumps(item)[:800]}"))
        return findings
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[graphql_cop_tool] WARNING: error running graphql-cop — {e}")
        return None


def _introspection_probe(endpoint: str, scan_id: str) -> List[Dict[str, Any]]:
    """No-binary fallback: if introspection is enabled, that alone is a reportable leak."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            endpoint, data=_INTROSPECTION_QUERY.encode(),
            headers={"Content-Type": "application/json", "User-Agent": "ArmorGuard/1.0"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if hasattr(e, "read") else ""
    except Exception as exc:
        print(f"[graphql_cop_tool] introspection probe failed: {exc}")
        return []

    if '"__schema"' in body or '"queryType"' in body:
        return [_finding(
            scan_id, "Medium", "GraphQL: Introspection Enabled",
            f"The GraphQL endpoint {endpoint} answers introspection queries, exposing the full "
            "schema (types, fields, mutations) to any client. This hands an attacker a map of "
            "the entire API surface.",
            "Disable introspection in production; restrict it to authenticated internal tooling.",
            f"Endpoint: {endpoint}\nIntrospection response received (schema disclosed).")]
    return []


def run_graphql_cop_scan(target_url: str, scan_id: str,
                         endpoints: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    endpoints = endpoints or []
    if not endpoints:
        print("[graphql_cop_tool] No GraphQL endpoint in fingerprint — skipping.")
        return []

    findings: List[Dict[str, Any]] = []
    for endpoint in endpoints[:3]:  # bound runtime
        print(f"[graphql_cop_tool] Auditing {endpoint}")
        cli = _run_cli(endpoint, scan_id)
        if cli is None:
            logging.info("[graphql_cop_tool] falling back to introspection probe for %s", endpoint)
            findings.extend(_introspection_probe(endpoint, scan_id))
        else:
            findings.extend(cli)
    print(f"[graphql_cop_tool] Completed — {len(findings)} finding(s).")
    return findings
