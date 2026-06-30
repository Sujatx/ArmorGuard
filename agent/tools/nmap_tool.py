import logging
import re
import subprocess
import uuid
from datetime import datetime
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
from agent.config import NMAP_PATH

# nmap port status lines: e.g. "80/tcp open http" or "5000/tcp open http Werkzeug/3.0.1"
_PORT_PATTERN = re.compile(r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?")


def run_nmap_scan(target: str, scan_id: str) -> Dict[str, Any]:
    """Run a non-privileged Nmap TCP Connect scan with service/version detection (-sV)
    against common ports of the target host.

    Governance (intent verification) is handled by the calling sub-agent's ArmorIQ gate,
    not inside the tool. This function just runs the scan and returns the raw output plus
    parsed open ports; the caller decides how to classify severity (LLM interpretation,
    with the deterministic table below as a fallback).

    Returns:
        {"raw": <full nmap stdout>, "host": <scanned host>,
         "ports": [(port:int, service:str, version:str), ...]}
    """
    # nmap only accepts hostnames/IPs, not full URLs — strip scheme and port
    parsed = urlparse(target)
    host = parsed.hostname or target
    print(f"[nmap_tool] Starting Nmap -sV scan against: {host} (from {target})")

    # A selected set of common ports keeps it fast; -sV adds real service/version banners.
    ports = "21,22,23,25,80,110,135,139,443,445,1433,3306,3389,5000,8000,8080"
    cmd = [NMAP_PATH, "-sT", "-sV", "--version-light", "-p", ports, host]

    try:
        # -sV is slower than a bare connect scan, so allow more headroom than before.
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout

        ports_parsed: List[Tuple[int, str, str]] = []
        for port_str, service, version in _PORT_PATTERN.findall(output):
            ports_parsed.append((int(port_str), service, (version or "").strip()))

        print(f"[nmap_tool] Completed scan. {len(ports_parsed)} open port(s) detected.")
        return {"raw": output, "host": host, "ports": ports_parsed}

    except subprocess.TimeoutExpired:
        print("[nmap_tool] Subprocess timeout expired.")
        return {"raw": "", "host": host, "ports": []}
    except FileNotFoundError:
        msg = f"[nmap_tool] '{NMAP_PATH}' not found on PATH — nmap is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return {"raw": "", "host": host, "ports": []}
    except Exception as e:
        print(f"[nmap_tool] WARNING: Error running nmap — {e}")
        return {"raw": "", "host": host, "ports": []}


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
    }


def skip_standard_web_ports(ports: List[Tuple[int, str, str]]) -> List[Tuple[int, str, str]]:
    """Remove port/service pairs that are expected on any public web server.

    Port 443 is the definition of a working HTTPS site — never a finding regardless of
    how nmap labels the service (ssl/http, https, http — CDN-fronted deployments vary).
    Port 80 alongside 443 is a standard redirect configuration — also not a finding."""
    port_numbers = {p for p, _, _ in ports}
    filtered = []
    for port, service, version in ports:
        if port == 443:
            continue
        if port == 80 and 443 in port_numbers:
            continue
        filtered.append((port, service, version))
    return filtered


def classify_ports_deterministic(ports: List[Tuple[int, str, str]], scan_id: str,
                                 raw_output: str) -> List[Dict[str, Any]]:
    """Static port→severity classifier used as a fallback when LLM interpretation is
    unavailable or returns nothing, so a scan never loses its nmap findings."""
    findings: List[Dict[str, Any]] = []
    for port, service, version in ports:
        svc = f"{service} {version}".strip()
        evidence = f"Port: {port}/tcp open {svc}"

        if port in (1433, 3306, 5432):
            findings.append(_finding(
                scan_id, "High", f"Exposed Database Service Port ({svc})",
                f"A database service ({svc}) was found listening on open port {port}. "
                "Exposing database services directly to the network increases the risk of "
                "unauthorized access, brute-force authentication attacks, or exploitation "
                "of database-specific vulnerabilities.",
                "Restrict network access to this database port using host-based firewalls "
                "or security groups. Configure the database to bind only to localhost "
                "(127.0.0.1) if external connections are not strictly required.",
                evidence))
        elif port in (22, 23, 3389):
            severity = "High" if port == 23 else "Medium"  # Telnet is plain-text
            desc = f"A remote management port ({svc}) is open on port {port}. "
            remediation = f"Disable public access to port {port}. "
            if port == 23:
                desc += ("Telnet transmits all credentials and data in cleartext, making it "
                         "highly vulnerable to sniffing and interception.")
                remediation += "Decommission Telnet immediately and replace it with SSH."
            else:
                desc += ("Exposing administrative interfaces (SSH/RDP) publicly increases "
                         "the risk of brute-force password cracking and exploitation.")
                remediation += ("Require VPN access to manage the host, or restrict access "
                                "to specific source IPs using firewall rules.")
            findings.append(_finding(
                scan_id, severity, f"Exposed Remote Management Port ({svc})",
                desc, remediation, evidence))
        elif port in (21, 80, 8080):
            findings.append(_finding(
                scan_id, "Medium", f"Exposed Unencrypted HTTP/FTP Service Port ({svc})",
                f"An unencrypted service ({svc}) is running on port {port}. Data transmitted "
                "over this port is sent in plain text and can be intercepted or modified by "
                "an attacker on the network path.",
                "Transition services to encrypted counterparts (HTTPS on 443, SFTP/FTPS "
                "instead of FTP). Disable the unencrypted endpoint or redirect HTTP to HTTPS.",
                evidence))
        elif port in (5000, 8000):
            findings.append(_finding(
                scan_id, "Low", f"Web Application Port Directly Exposed ({port})",
                f"Port {port} is open and appears to be running a web application. Nmap "
                f"identified the service as '{svc}'. In production, application servers on "
                "this port should sit behind a reverse proxy rather than being directly "
                "reachable.",
                "Place the application behind a reverse proxy (nginx, caddy, or a cloud load "
                "balancer) that handles TLS termination and forwards traffic internally.",
                evidence))
        else:
            findings.append(_finding(
                scan_id, "Low", f"Unexpected Open Port ({port}/{service})",
                f"TCP port {port} (reported service: '{svc}') is open and accepting "
                "connections. If this port is not intentionally part of the application's "
                "network surface, its presence increases exposure to opportunistic attacks.",
                "Verify whether this port belongs to a known service. If not required, "
                "disable the service and close the port via firewall rules. Document all "
                "intentionally open ports in a network runbook.",
                evidence))
    return findings
