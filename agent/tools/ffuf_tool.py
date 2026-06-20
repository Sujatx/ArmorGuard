import json
import logging
import os
import subprocess
import tempfile
from typing import List
from urllib.parse import urlparse

from agent.config import FFUF_PATH, FFUF_WORDLIST


def run_ffuf_scan(target_url: str, scan_id: str) -> List[str]:
    """Brute-force routes on the target with ffuf.

    Discovery stage for headless APIs: where katana (a crawler) finds nothing because
    routes aren't linked, ffuf probes a wordlist of common paths and returns the ones
    that respond. Recursion follows discovered directories one level deep.

    Returns the list of discovered route URLs (no findings of its own).
    """
    base = target_url.rstrip("/")
    print(f"[ffuf_tool] Brute-forcing routes on {base} with wordlist {FFUF_WORDLIST}")

    if not os.path.exists(FFUF_WORDLIST):
        msg = f"[ffuf_tool] Wordlist not found: {FFUF_WORDLIST} — skipping route brute-force."
        logging.warning(msg)
        print(msg)
        return []

    fd, outfile = tempfile.mkstemp(prefix="ffuf_", suffix=".json")
    os.close(fd)
    try:
        cmd = [
            FFUF_PATH,
            "-u", f"{base}/FUZZ",
            "-w", FFUF_WORDLIST,
            "-mc", "200,204,301,302,307,401,403,405,500",  # match anything but 404
            "-t", "40",
            "-recursion", "-recursion-depth", "1",
            "-of", "json", "-o", outfile,
            "-s",
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        with open(outfile) as fh:
            data = json.load(fh)

        scope_host = urlparse(target_url).hostname
        urls: list = []
        for res in data.get("results", []):
            u = res.get("url")
            if u and urlparse(u).hostname == scope_host:
                urls.append(u)

        urls = sorted(dict.fromkeys(urls))
        print(f"[ffuf_tool] Discovered {len(urls)} route(s).")
        return urls

    except subprocess.TimeoutExpired:
        print("[ffuf_tool] WARNING: ffuf timed out.")
        return []
    except FileNotFoundError:
        msg = f"[ffuf_tool] '{FFUF_PATH}' not found on PATH — ffuf is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[ffuf_tool] WARNING: Error running ffuf — {e}")
        return []
    finally:
        try:
            os.remove(outfile)
        except OSError:
            pass
