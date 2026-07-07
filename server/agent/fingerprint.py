"""Fingerprint phase — derive structured signals about the target.

This is the first phase of the intent-driven pipeline. It runs the lightweight probes
(nmap port scan, an HTTP header probe, katana crawl) and distils them into a single
``fingerprints`` dict. Unlike the deterministic recon phase, it emits **no findings** —
raw observations (missing headers, open app ports) are context here, not vulnerabilities.
The Select phase reads these signals to decide which exploitation-tier tools are eligible,
and each tool's eligibility predicate (agent._eligible_*) reads the same fields.

Signal shape (mirrors models.Fingerprint):
    open_ports, server, tech[], headers{}, auth_scheme, has_jwt, jwt_sample,
    graphql_endpoints[], java_markers, oracle_listener, endpoints[], param_urls[]
"""
import re
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from agent.tools.nmap_tool import run_nmap_scan
from agent.tools.katana_tool import run_katana_crawl
from agent.tools.ffuf_tool import run_ffuf_scan
from agent.tools.arjun_tool import run_arjun_scan

# A JWT is three base64url segments separated by dots, starting with the standard
# {"alg":...} header which base64url-encodes to a leading "eyJ".
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Cookie-name / header substrings → stack marker (lowercased match).
_TECH_COOKIE_MARKERS = {
    "phpsessid": "php",
    "laravel_session": "laravel",
    "ci_session": "codeigniter",
    "jsessionid": "java",
    "asp.net": "asp.net",
    "connect.sid": "express",
    "csrftoken": "django",
    "_rails": "rails",
}
_TECH_HEADER_MARKERS = {
    "x-powered-by": None,      # value carries the marker verbatim
    "x-aspnet-version": "asp.net",
    "x-drupal-cache": "drupal",
    "x-generator": None,
}


def _probe_candidates(target_url: str) -> list:
    """URLs to try, in order. A bare host (no scheme) becomes https-then-http; an
    explicit https URL still gets an http fallback in case the host is plaintext-only.
    urllib.request.Request rejects a schemeless URL outright, so this must run before it."""
    if "://" not in target_url:
        return ["https://" + target_url, "http://" + target_url]
    if target_url.startswith("https://"):
        return [target_url, "http://" + target_url[len("https://"):]]
    return [target_url]


def _http_probe(target_url: str) -> Tuple[Dict[str, str], int, str]:
    """Single GET returning (normalised headers, status, body-preview). Never raises —
    accepts bare hosts and degrades to empty signals if every candidate URL fails."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for url in _probe_candidates(target_url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ArmorGuard/1.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
                msg = resp.headers
                status = resp.status
                body = resp.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            # A 4xx/5xx is still a successful fingerprint — the headers are what we want.
            msg = e.headers
            status = e.code
            try:
                body = e.read(20000).decode("utf-8", "replace")
            except Exception:
                body = ""
        except Exception as exc:
            print(f"[fingerprint] HTTP probe failed for {url}: {exc}")
            continue
        raw = dict(msg)
        # dict() keeps only one value per header name; a response that sets several cookies
        # (e.g. a session cookie *and* a JWT) would lose all but one, silently dropping the
        # `has_jwt` signal. Re-join every Set-Cookie so the JWT is always visible downstream.
        cookies = msg.get_all("Set-Cookie") if hasattr(msg, "get_all") else None
        if cookies:
            raw["Set-Cookie"] = "; ".join(cookies)
        headers = {k.lower(): v for k, v in raw.items()}
        return headers, status, body
    return {}, 0, ""


def _detect_tech(headers: Dict[str, str]) -> List[str]:
    tech: set = set()
    server = (headers.get("server") or "").lower()
    for name in ("nginx", "apache", "iis", "werkzeug", "gunicorn", "express", "caddy"):
        if name in server:
            tech.add(name)
    set_cookie = (headers.get("set-cookie") or "").lower()
    for marker, label in _TECH_COOKIE_MARKERS.items():
        if marker in set_cookie:
            tech.add(label)
    for header_name, label in _TECH_HEADER_MARKERS.items():
        val = headers.get(header_name)
        if val:
            tech.add(label if label else val.split("/")[0].strip().lower())
    return sorted(t for t in tech if t)


def _detect_auth(headers: Dict[str, str], body: str) -> Tuple[str, bool, str]:
    """Return (auth_scheme, has_jwt, jwt_sample)."""
    www_auth = (headers.get("www-authenticate") or "").lower()
    set_cookie = headers.get("set-cookie") or ""
    auth_header = headers.get("authorization") or ""

    jwt_match = (_JWT_RE.search(set_cookie) or _JWT_RE.search(auth_header)
                 or _JWT_RE.search(body))
    jwt_sample = jwt_match.group(0) if jwt_match else ""

    if jwt_sample:
        return "jwt", True, jwt_sample
    if "basic" in www_auth:
        return "basic", False, ""
    if "saml" in body.lower() or "samlrequest" in body.lower():
        return "saml", False, ""
    if "<form" in body.lower() and ("password" in body.lower()):
        return "form", False, ""
    return "none", False, ""


def _detect_java_markers(headers: Dict[str, str], body: str, endpoints: List[str]) -> bool:
    set_cookie = (headers.get("set-cookie") or "").lower()
    if "jsessionid" in set_cookie:
        return True
    if "__viewstate" in body.lower():
        return True
    return any(e.lower().endswith((".do", ".action", ".jsp")) or ".do?" in e.lower()
               or ".action?" in e.lower() for e in endpoints)


def _detect_graphql(target_url: str, endpoints: List[str]) -> List[str]:
    found = [e for e in endpoints if "/graphql" in e.lower() or "/gql" in e.lower()]
    if found:
        return sorted(dict.fromkeys(found))
    # Probe the two conventional locations even if the crawler didn't surface them.
    # Use the scheme-normalised form so a bare host (e.g. "example.com") yields a valid URL.
    base = _probe_candidates(target_url)[0].rstrip("/") + "/"
    candidates = [urljoin(base, "graphql"), urljoin(base, "api/graphql")]
    live: List[str] = []
    for url in candidates:
        try:
            req = urllib.request.Request(
                url, data=b'{"query":"{__typename}"}',
                headers={"Content-Type": "application/json", "User-Agent": "ArmorGuard/1.0"},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                body = resp.read(4000).decode("utf-8", "replace")
            if "__typename" in body or '"data"' in body or "graphql" in body.lower():
                live.append(url)
        except Exception:
            continue
    return live


def build_fingerprint(target_url: str, scan_id: str) -> Dict[str, Any]:
    """Run the probes and return the structured signals dict. Best-effort throughout —
    any single probe failing degrades that signal, never the whole fingerprint."""
    # 1. Ports (nmap) — also gives us the Oracle listener signal.
    nmap = run_nmap_scan(target_url, scan_id)
    open_ports = [{"port": p, "service": s, "version": v} for p, s, v in nmap.get("ports", [])]
    port_numbers = {p["port"] for p in open_ports}
    oracle_listener = 1521 in port_numbers

    # 2. HTTP surface (headers, auth, tech).
    headers, status, body = _http_probe(target_url)
    server = headers.get("server")
    tech = _detect_tech(headers)
    auth_scheme, has_jwt, jwt_sample = _detect_auth(headers, body)

    # 3. Endpoint map (katana) — passive crawl of linked routes.
    try:
        endpoints, param_urls = run_katana_crawl(target_url, scan_id)
    except Exception as exc:
        print(f"[fingerprint] katana crawl failed: {exc}")
        endpoints, param_urls = [target_url], []

    # 3b. Active discovery. A passive crawl alone routinely surfaces zero parameters on a
    # real site, which starves the injection tools — sqlmap/commix only run once a parameter
    # exists (see _eligible_params). ffuf brute-forces unlinked routes; arjun probes known
    # routes for hidden query params. Both degrade to [] on failure and never raise, so a
    # discovery miss weakens the surface signal without breaking the fingerprint.
    try:
        ffuf_routes = run_ffuf_scan(target_url, scan_id)
        if ffuf_routes:
            endpoints = sorted(dict.fromkeys(endpoints + ffuf_routes))
    except Exception as exc:
        print(f"[fingerprint] ffuf route discovery failed: {exc}")

    # arjun exists solely to find parameters when passive discovery found none. If katana
    # (or ffuf) already surfaced parameterised URLs, arjun is pure wasted time — skip it.
    # It is slow (serial --stable probing), so this skip is the single biggest scan-time win.
    if param_urls:
        print(f"[fingerprint] arjun skipped — {len(param_urls)} parameterised URL(s) already discovered")
    else:
        try:
            # arjun is slow per-URL, so probe the base plus the most promising discovered
            # routes rather than every endpoint.
            arjun_targets = (endpoints or [target_url])[:12]
            found_params = run_arjun_scan(arjun_targets, scan_id)
            if found_params:
                param_urls = sorted(dict.fromkeys(param_urls + found_params))
        except Exception as exc:
            print(f"[fingerprint] arjun param discovery failed: {exc}")

    java_markers = _detect_java_markers(headers, body, endpoints)
    graphql_endpoints = _detect_graphql(target_url, endpoints)

    fp: Dict[str, Any] = {
        "open_ports": open_ports,
        "server": server,
        "tech": tech,
        "headers": headers,
        "auth_scheme": auth_scheme,
        "has_jwt": has_jwt,
        "jwt_sample": jwt_sample,
        "graphql_endpoints": graphql_endpoints,
        "java_markers": java_markers,
        "oracle_listener": oracle_listener,
        "endpoints": endpoints,
        "param_urls": param_urls,
        "status": status,
    }
    return fp


def summarize_fingerprint(fp: Dict[str, Any]) -> str:
    """One-line human digest for the UI / agent_reasoning stream."""
    bits = []
    if fp.get("server"):
        bits.append(f"server={fp['server']}")
    if fp.get("tech"):
        bits.append("tech=" + "/".join(fp["tech"]))
    bits.append(f"auth={fp.get('auth_scheme', 'none')}")
    if fp.get("has_jwt"):
        bits.append("JWT present")
    if fp.get("graphql_endpoints"):
        bits.append(f"GraphQL×{len(fp['graphql_endpoints'])}")
    if fp.get("java_markers"):
        bits.append("Java surface")
    if fp.get("oracle_listener"):
        bits.append("Oracle:1521")
    bits.append(f"{len(fp.get('endpoints', []))} endpoint(s), "
                f"{len(fp.get('param_urls', []))} parameterised")
    return "; ".join(bits)
