"""Static finding enrichment — CVSS / CWE / OWASP / compliance taxonomy.

Every confirmed finding is tagged with industry-standard metadata so the report reads
like professional pentest collateral: a CVSS 3.1 vector + base score, a CWE id, the OWASP
Top-10 (2021) category, the MITRE ATT&CK technique, and mappings to the two compliance
frameworks enterprise buyers ask for most — PCI-DSS and SOC 2.

Design decision: this is a **static lookup keyed by finding type**, not LLM-generated. A CVSS
vector must be exact and audit-defensible; a model hallucinating "AV:L" where it should be
"AV:N" would quietly misrate severity. The LLM's job is the *narrative* (business impact,
executive summary), never the taxonomy. Values here are the standard ratings for the
canonical form of each vulnerability class; a specific finding can still carry a
higher/lower severity set by its tool, but the taxonomy (CWE/OWASP/CVSS vector) is stable.

Finding-type keys mirror confirm.CONFIRMERS: sql_injection, command_injection, jwt,
graphql, oracle. ``enrich(finding_type)`` returns a dict of the fields below; unknown
types return an empty dict so callers degrade gracefully.
"""
from typing import Any, Dict


# CVSS 3.1 base scores are the standard ratings for the canonical form of each class.
# Vectors are written out so the report can show the full string (enterprise reviewers
# recompute them). Compliance ids reference the specific control/requirement, not just
# the framework name, so an auditor can trace the mapping.
_ENRICHMENT: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp_category": "A03:2021 – Injection",
        "technique_id": "T1190",
        "business_impact": (
            "An attacker can read, modify, or delete any data in the connected database — "
            "customer records, credentials, and financial data — and in many configurations "
            "escalate to full server compromise. This is a direct path to a reportable data breach."
        ),
        "compliance": {
            "pci_dss": "6.5.1 – Injection flaws (SQL injection)",
            "soc2": "CC6.1 – Logical access controls protect information assets",
        },
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "command_injection": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "owasp_category": "A03:2021 – Injection",
        "technique_id": "T1059",
        "business_impact": (
            "An attacker can execute arbitrary operating-system commands on the host with the "
            "web service's privileges, enabling data theft, lateral movement across the internal "
            "network, and full server takeover."
        ),
        "compliance": {
            "pci_dss": "6.5.1 – Injection flaws (OS command injection)",
            "soc2": "CC6.1 – Logical access controls protect information assets",
        },
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
    "jwt": {
        # alg:none / unverified-signature forgery → authentication bypass. C:H/I:H, A:N.
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-347",
        "cwe_name": "Improper Verification of Cryptographic Signature",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "technique_id": "T1606",
        "business_impact": (
            "An attacker can forge authentication tokens and impersonate any user — including "
            "administrators — bypassing login entirely and gaining unauthorized access to "
            "protected functionality and data."
        ),
        "compliance": {
            "pci_dss": "6.5.10 – Broken authentication and session management",
            "soc2": "CC6.1 – Logical access controls protect information assets",
        },
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ],
    },
    "graphql": {
        # Introspection / field-suggestion disclosure — information exposure baseline.
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "technique_id": "T1595",
        "business_impact": (
            "Exposed schema introspection lets an attacker map the full API surface — hidden "
            "types, fields, and operations — accelerating targeted attacks and potentially "
            "leaking sensitive data structures."
        ),
        "compliance": {
            "pci_dss": "6.5.5 – Improper error handling / information leakage",
            "soc2": "CC6.1 – Logical access controls protect information assets",
        },
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        ],
    },
    "oracle": {
        # Exposed Oracle TNS listener / SID enumeration — network-exposed data service.
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-284",
        "cwe_name": "Improper Access Control",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "technique_id": "T1190",
        "business_impact": (
            "An exposed Oracle listener lets an attacker enumerate database identifiers and "
            "attempt unauthorized access to the database service, potentially exposing all data "
            "it holds."
        ),
        "compliance": {
            "pci_dss": "2.2 – Secure configuration standards for system components",
            "soc2": "CC6.6 – Boundary protection restricts external access",
        },
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
}


def cvss_rating(score: float) -> str:
    """CVSS 3.1 qualitative severity band for a base score."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def enrich(finding_type: str) -> Dict[str, Any]:
    """Return the taxonomy dict for a finding type, or {} if unknown.

    A copy is returned so callers can safely merge in per-finding values (e.g. a
    finding-specific ``compliance`` addition) without mutating the shared table.
    """
    base = _ENRICHMENT.get((finding_type or "").lower())
    if not base:
        return {}
    out: Dict[str, Any] = dict(base)
    out["compliance"] = dict(base.get("compliance", {}))
    out["references"] = list(base.get("references", []))
    out["cvss_severity"] = cvss_rating(out.get("cvss_score", 0.0))
    return out


def compliance_tags(finding_type: str) -> list:
    """Flat list of compliance tag strings for a finding type — convenient for the
    report's tag row. E.g. ['OWASP A03:2021', 'PCI-DSS 6.5.1', 'SOC 2 CC6.1']."""
    e = enrich(finding_type)
    if not e:
        return []
    tags = []
    owasp = e.get("owasp_category", "")
    if owasp:
        # "A03:2021 – Injection" → "OWASP A03:2021"
        tags.append("OWASP " + owasp.split(" ")[0].rstrip("–").strip())
    comp = e.get("compliance", {})
    if comp.get("pci_dss"):
        tags.append("PCI-DSS " + comp["pci_dss"].split(" ")[0])
    if comp.get("soc2"):
        tags.append("SOC 2 " + comp["soc2"].split(" ")[0])
    return tags
