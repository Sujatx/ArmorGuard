import json
import logging
import os
import subprocess
import tempfile
from typing import List

from agent.config import ARJUN_PATH


def run_arjun_scan(urls: List[str], scan_id: str) -> List[str]:
    """Discover hidden query parameters on the given routes with arjun.

    Bridges discovery → injection: a route like /api/products is useless to sqlmap
    until we know it takes `?id=`. arjun fuzzes for accepted parameters and we hand the
    resulting parameterised URLs to sqlmap.

    Returns a list of URLs with discovered parameters attached (e.g. /api/products?id=1).
    """
    candidates = list(dict.fromkeys(urls or []))[:4]  # cap to bound runtime
    if not candidates:
        return []
    print(f"[arjun_tool] Probing {len(candidates)} route(s) for hidden parameters")

    tmpdir = tempfile.mkdtemp(prefix="arjun_")
    infile = os.path.join(tmpdir, "urls.txt")
    outfile = os.path.join(tmpdir, "out.json")
    try:
        with open(infile, "w") as fh:
            fh.write("\n".join(candidates))

        # --stable: probe slowly/serially so rate-limited targets (e.g. a single-threaded
        # dev server) don't cause arjun to bail. Slower but reliable on real apps.
        # Kept for reliability, but total cost is bounded by the small candidate cap above
        # plus a short timeout — a worst-case hang now costs ~50s instead of ~4 minutes.
        cmd = [ARJUN_PATH, "-i", infile, "-oJ", outfile, "-m", "GET", "--stable"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=50)

        if not os.path.exists(outfile):
            print("[arjun_tool] No parameters discovered.")
            return []
        with open(outfile) as fh:
            data = json.load(fh)

        param_urls: list = []
        # arjun -oJ is keyed by URL → {url: {"params": [...], "method": ...}}
        for url, info in (data.items() if isinstance(data, dict) else []):
            params = info.get("params") if isinstance(info, dict) else info
            if params:
                query = "&".join(f"{p}=1" for p in params)
                sep = "&" if "?" in url else "?"
                param_urls.append(f"{url}{sep}{query}")

        param_urls = sorted(dict.fromkeys(param_urls))
        print(f"[arjun_tool] Found {len(param_urls)} parameterised URL(s).")
        return param_urls

    except subprocess.TimeoutExpired:
        print("[arjun_tool] WARNING: arjun timed out.")
        return []
    except FileNotFoundError:
        msg = f"[arjun_tool] '{ARJUN_PATH}' not found on PATH — arjun is not installed. Skipping."
        logging.warning(msg)
        print(msg)
        return []
    except Exception as e:
        print(f"[arjun_tool] WARNING: Error running arjun — {e}")
        return []
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
