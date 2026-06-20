# ArmorGuard Known Issues for HackBriven Demo

This document captures the remaining known issues across all owners before the final demo.

## Priority Order for Demo Day

| Priority | Issue | Owner | Blocks Demo? |
|---|---|---|---|
| 🔴 **Critical** | **Frontend not built**<br>The `frontend/src/app/` directory exists but no required pages are implemented (no scan flow, no live terminal, no report view, no incident panel). | Kirti | **Yes** — The entire demo story is visual; without the frontend, nothing can be shown. |
| 🔴 **Critical** | **WebSocket drops immediately (Live stream broken)**<br>The scan runs as a FastAPI background task which starts before the WS connects. The WS connection immediately returns 1000 (OK) and falls back to polling. The live scan terminal on the frontend will never show real-time tool status or drift events. | Sujat | **Yes** — Even if the frontend is built, no live events will stream to it. |
| 🟠 **High** | **LLM might not call `http_request` (Non-deterministic)**<br>The prompt injection demo relies on Groq's LLM deciding to obey a hidden HTML comment. If the LLM behaves securely and ignores the comment, the `http_request` tool is never called, and the ArmorIQ block never happens. | Parth | Partially — The ArmorIQ governance story could silently fail during the live presentation. |
| 🟡 **Medium** | **Port 3306 not detected by nmap**<br>The demo-target opens port 3306 internally via a socket thread, but nmap scanning from the backend container only detects port 5000 (gunicorn). The dummy port may not be correctly exposed or reachable via the Docker bridge network. | Kanishk | Partial — Loses one specific finding category. |
| 🟢 **Resolved** | **sqlmap found 0 findings**<br>The `/user?id=` SQLi endpoint existed, but scanners (katana/arjun) had no way to discover it because there was no link to it. *FIXED: Added hidden `<a href="/user?id=1">` to `app.py`.* | Kanishk | No — Fixed. |
| 🟢 **Resolved** | **Kanishk's build tracker not updated**<br>The planted vulnerabilities and verification steps were done but `PROJECT.md` still had `[ ]`. *FIXED: Updated PROJECT.md tracker to `[x]`.* | Kanishk | No — Fixed. |
