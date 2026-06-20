import logging
import re
import subprocess
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from agent.config import NMAP_PATH

def run_nmap_scan(
    target: str, 
    scan_id: str, 
    client: Optional[Any] = None, 
    intent_token: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """Runs a non-privileged Nmap TCP Connect scan (-sT) against common ports of the target host.
    Every call is validated in real-time by the ArmorIQ client before execution.
    
    Args:
        target: The target hostname or IP address.
        scan_id: The active scan identifier.
        client: The ArmorIQ client wrapper instance.
        intent_token: The signed intent token.
        
    Returns:
        List of findings matching the Finding shape contract.
    """
    # nmap only accepts hostnames/IPs, not full URLs — strip scheme and port
    parsed = urlparse(target)
    host = parsed.hostname or target
    print(f"[nmap_tool] Starting Nmap scan against: {host} (from {target})")

    # 1. Perform ArmorIQ Intent Verification before execution
    if client is not None and intent_token is not None:
        print("[nmap_tool] Verifying intent with ArmorIQ...")
        client.invoke(
            mcp="agent_tools",
            action="nmap",
            intent_token=intent_token,
            params={"target": target}
        )
        print("[nmap_tool] Intent verified successfully by ArmorIQ.")

    # We scan a selected set of common ports to keep it fast
    ports = "21,22,23,25,80,110,135,139,443,445,1433,3306,3389,5000,8000,8080"
    cmd = [
        NMAP_PATH,
        "-sT",
        "-p", ports,
        host
    ]
    
    try:
        # Run subprocess with timeout (30 seconds)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        
        # Regex to parse nmap port status lines: e.g. "80/tcp open http"
        port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\S+)")
        matches = port_pattern.findall(output)
        
        findings = []
        
        for port_str, service in matches:
            port = int(port_str)
            evidence = f"Port: {port}/tcp\nState: open\nService: {service}\nRaw Scan Output Snippet:\n{output}"
            
            # Map exposed ports to security findings based on severity rules
            if port in [1433, 3306, 5432]:
                findings.append({
                    "findingId": str(uuid.uuid4()),
                    "scanId": scan_id,
                    "severity": "High",
                    "title": f"Exposed Database Service Port ({service})",
                    "description": f"A database service ({service}) was found listening on open port {port}. Exposing database services directly to the network increases the risk of unauthorized access, brute-force authentication attacks, or exploitation of database-specific vulnerabilities.",
                    "remediation": "Restrict network access to this database port using host-based firewalls (e.g. iptables, Windows Firewall) or security groups. Configure the database daemon to bind only to localhost (127.0.0.1) if external connections are not strictly required.",
                    "evidence": evidence,
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                })
            elif port in [22, 23, 3389]:
                severity = "High" if port == 23 else "Medium"  # Telnet is plain-text, hence High severity
                title = f"Exposed Remote Management Port ({service})"
                desc = f"A remote management port ({service}) is open on port {port}. "
                if port == 23:
                    desc += "Telnet transmits all credentials and data in cleartext, making it highly vulnerable to sniffing and interception."
                else:
                    desc += "Exposing administrative management interfaces (like SSH or RDP) publicly increases the risk of brute-force password cracking and target exploitation."
                    
                remediation = f"Disable public access to port {port}. "
                if port == 23:
                    remediation += "Decommission Telnet immediately and replace it with secure protocols like SSH."
                else:
                    remediation += "Require VPN access to manage the host, or restrict access to specific source IP addresses using firewall rules."
                    
                findings.append({
                    "findingId": str(uuid.uuid4()),
                    "scanId": scan_id,
                    "severity": severity,
                    "title": title,
                    "description": desc,
                    "remediation": remediation,
                    "evidence": evidence,
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                })
            elif port in [21, 80, 8080]:
                findings.append({
                    "findingId": str(uuid.uuid4()),
                    "scanId": scan_id,
                    "severity": "Medium",
                    "title": f"Exposed Unencrypted HTTP/FTP Service Port ({service})",
                    "description": f"An unencrypted service ({service}) is running on port {port}. Data transmitted over this port is sent in plain text and can be intercepted or modified by an attacker positioned on the network path.",
                    "remediation": "Transition services to their encrypted counterparts (e.g. use HTTPS instead of HTTP on port 443, or SFTP/FTPS instead of FTP). Disable the unencrypted endpoint or redirect unencrypted HTTP traffic to HTTPS.",
                    "evidence": evidence,
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                })
            else:
                findings.append({
                    "findingId": str(uuid.uuid4()),
                    "scanId": scan_id,
                    "severity": "Low",
                    "title": f"Open TCP Port Detected ({port}/{service})",
                    "description": f"The TCP port {port} running service '{service}' was found to be open and accepting connections. Running unnecessary services increases the attack surface of the system.",
                    "remediation": "Review the service running on this port and shut it down if it is not required for business operations. Secure the service with proper authentication and access control lists if it must remain open.",
                    "evidence": evidence,
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                })
                
        print(f"[nmap_tool] Completed scan. Found {len(findings)} open ports mapped to findings.")
        return findings
        
    except subprocess.TimeoutExpired:
        print("[nmap_tool] Subprocess timeout expired.")
        return []
    except FileNotFoundError:
        msg = f"[nmap_tool] '{NMAP_PATH}' not found on PATH — nmap is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[nmap_tool] WARNING: Error running nmap — {e}")
        return []
