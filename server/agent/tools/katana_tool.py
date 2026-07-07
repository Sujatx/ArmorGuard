import json
import logging
import subprocess
from typing import List, Tuple
from urllib.parse import urlparse

from agent.config import KATANA_PATH


def run_katana_crawl(target_url: str, scan_id: str) -> Tuple[List[str], List[str]]:
    """Crawl the target with katana to map its attack surface.

    This is the discovery stage: it does not itself report vulnerabilities. It returns
    the endpoints it found so the attack tools (nuclei, sqlmap) can hit real routes
    instead of just the base URL.

    Returns:
        (urls, param_urls) — all discovered endpoints, and the subset that carry query
        parameters (the candidates worth handing to sqlmap / injection testing).
    """
    print(f"[katana_tool] Crawling target for endpoints: {target_url}")

    # Stay on the target host only — never let the crawl wander off-scope.
    scope_host = urlparse(target_url).hostname or ""

    cmd = [
        KATANA_PATH,
        "-u", target_url,
        "-silent",
        "-jc",            # parse JS files for endpoints (no headless browser needed)
        "-d", "2",        # crawl depth
        "-c", "10",       # concurrency
        "-timeout", "10",
        "-jsonl",         # katana >=1.6 renamed -json → -jsonl; the old flag hard-errors
    ]
    if scope_host:
        cmd += ["-fs", "fqdn"]  # field-scope: stay on the same fully-qualified host

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=75)
        output = result.stdout.strip()

        # A non-zero exit with no output means katana rejected the invocation itself
        # (e.g. an unknown flag after a version bump). Surface it loudly — silently
        # falling back to "base URL only" here starves param discovery and, downstream,
        # the entire exploit tier (sqlmap/commix never see a parameter to test).
        if result.returncode != 0 and not output:
            print(f"[katana_tool] WARNING: katana exited {result.returncode} with no output — "
                  f"discovery disabled. stderr: {result.stderr.strip()[:300]}")

        urls: set = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            endpoint = (obj.get("request", {}) or {}).get("endpoint") or obj.get("endpoint")
            if endpoint:
                urls.add(endpoint)

        # Always include the base target so attack tools have at least one target even
        # if the crawl came up empty (e.g. a JSON API with no crawlable links).
        urls.add(target_url)

        all_urls = sorted(urls)
        param_urls = sorted(u for u in all_urls if "?" in u and "=" in u)

        print(f"[katana_tool] Discovered {len(all_urls)} endpoint(s), "
              f"{len(param_urls)} with parameters.")
        return all_urls, param_urls

    except subprocess.TimeoutExpired:
        print("[katana_tool] WARNING: katana crawl timed out — returning base target only.")
        return [target_url], []
    except FileNotFoundError:
        msg = f"[katana_tool] '{KATANA_PATH}' not found on PATH — katana is not installed. Skipping discovery."
        logging.warning(msg)
        print(msg)
        return [target_url], []
    except Exception as e:
        print(f"[katana_tool] WARNING: Error running katana — {e}")
        return [target_url], []
