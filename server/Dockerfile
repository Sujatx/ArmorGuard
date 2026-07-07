FROM python:3.11-slim

# Pinned scanner versions — bump these ARGs to upgrade. Pinning keeps demo-day
# builds reproducible and avoids a "latest" surprise mid-rehearsal.
ARG NUCLEI_VERSION=3.9.0
ARG HTTPX_VERSION=1.9.0
ARG KATANA_VERSION=1.6.1
ARG FFUF_VERSION=2.1.0

# Install system dependencies. nmap from apt; unzip/ca-certificates needed to
# fetch and unpack the ProjectDiscovery release binaries below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    perl \
    libnet-ssleay-perl \
    libjson-perl \
    libxml-writer-perl \
    git \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# perl + these perl modules are runtime deps for nikto (installed from source below;
# the package is not in the slim image's apt repos). libjson-perl/libxml-writer-perl
# are needed for nikto's JSON output.

# Retry helpers — the BuildKit builder's network path has been observed to intermittently
# fail or time out reaching github.com (both `git clone` and plain `curl` downloads of
# release assets) on platforms like Render, even though the host and a plain `docker run`
# container reach it fine. Defined once, up front, so every download below — git clone or
# curl — survives a transient blip instead of failing the whole build.
RUN printf '#!/bin/sh\nset -e\nurl="$1"; dest="$2"\nfor i in 1 2 3 4 5; do\n  if git clone --depth 1 "$url" "$dest"; then exit 0; fi\n  echo "[retry-clone] attempt $i failed, retrying in 5s..." >&2\n  rm -rf "$dest"\n  sleep 5\ndone\nexit 1\n' > /usr/local/bin/retry-clone \
    && chmod +x /usr/local/bin/retry-clone \
    && printf '#!/bin/sh\nset -e\nurl="$1"; out="$2"\nfor i in 1 2 3 4 5; do\n  if curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$out"; then exit 0; fi\n  echo "[retry-curl] attempt $i failed, retrying in 5s..." >&2\n  rm -f "$out"\n  sleep 5\ndone\nexit 1\n' > /usr/local/bin/retry-curl \
    && chmod +x /usr/local/bin/retry-curl

# Single canonical scanner-binary location: /opt/tools, given PATH precedence below.
# IMPORTANT: the Python `httpx` library (pulled in by supabase/pydantic-ai) installs
# its own `httpx` console script into /usr/local/bin during pip install. Keeping the
# ProjectDiscovery `httpx` scanner in /opt/tools *ahead* of /usr/local/bin on PATH
# ensures `httpx` resolves to the scanner, not the Python lib's CLI.
# nuclei + httpx + katana (ProjectDiscovery) — pinned release binaries.
# katana is the discovery crawler: it maps the target's endpoints/parameters so the
# attack tools (nuclei, sqlmap) hit real routes instead of just the base URL.
RUN mkdir -p /opt/tools \
    && retry-curl "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /opt/tools/nuclei \
    && chmod +x /opt/tools/nuclei \
    && retry-curl "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip -d /tmp/httpx \
    && mv /tmp/httpx/httpx /opt/tools/httpx \
    && chmod +x /opt/tools/httpx \
    && retry-curl "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" /tmp/katana.zip \
    && unzip -q /tmp/katana.zip -d /tmp/katana \
    && mv /tmp/katana/katana /opt/tools/katana \
    && chmod +x /opt/tools/katana \
    && retry-curl "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /opt/tools ffuf \
    && chmod +x /opt/tools/ffuf \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei /tmp/httpx.zip /tmp/httpx /tmp/katana.zip /tmp/katana /tmp/ffuf.tar.gz

# nikto — installed from source (not packaged in the slim image's apt repos). A small
# wrapper preserves nikto's program dir so it finds its config/plugins.
RUN retry-clone https://github.com/sullo/nikto /opt/nikto \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# --- Intent-driven roster: headless CLI offensive tools (git-installed, PATH wrappers) ---
# jwt_tool (ticarpi) — JWT weakness tester. commix — OS command-injection tester. Both run
# under the system python3; the wrapper scripts put them on PATH under the names the tool
# modules expect (JWT_TOOL_PATH=jwt_tool, COMMIX_PATH=commix). The Python tool modules
# degrade gracefully if a binary is missing, so odat (heavy Oracle client) stays opt-in.
RUN retry-clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && pip install --no-cache-dir pycryptodomex termcolor cprint requests \
    && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool \
    && retry-clone https://github.com/commixproject/commix /opt/commix \
    && printf '#!/bin/sh\nexec python3 /opt/commix/commix.py "$@"\n' > /usr/local/bin/commix \
    && chmod +x /usr/local/bin/commix

# graphql-cop (dolevf) — GraphQL misconfiguration auditor. Not published to PyPI, so it's
# git-installed here rather than listed in requirements.txt.
RUN retry-clone https://github.com/dolevf/graphql-cop /opt/graphql-cop \
    && pip install --no-cache-dir -r /opt/graphql-cop/requirements.txt \
    && printf '#!/bin/sh\nexec python3 /opt/graphql-cop/graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop \
    && chmod +x /usr/local/bin/graphql-cop

# odat (Oracle Database Attacking Tool) is opt-in: it needs the Oracle Instant Client and
# is only ever eligible when nmap finds an open 1521 listener. Build with
# --build-arg INSTALL_ODAT=true to include it; otherwise the odat tool no-ops.
ARG INSTALL_ODAT=false
RUN if [ "$INSTALL_ODAT" = "true" ]; then \
      retry-clone https://github.com/quentinhardy/odat /opt/odat \
      && pip install --no-cache-dir cx_Oracle python-libnmap passlib pycryptodome \
      && printf '#!/bin/sh\nexec python3 /opt/odat/odat.py "$@"\n' > /usr/local/bin/odat \
      && chmod +x /usr/local/bin/odat ; \
    else echo "[build] odat skipped (INSTALL_ODAT=false)"; fi


# Bundled wordlist for ffuf route brute-forcing (includes multi-level API paths so it
# can discover endpoints like /api/products that a crawler never sees).
COPY scripts/wordlists/common.txt /opt/tools/wordlists/common.txt

# Put the scanner dir ahead of /usr/local/bin so the ProjectDiscovery httpx wins.
ENV PATH="/opt/tools:${PATH}"

# Ship the nuclei template DB inside the image so the first scan does not have to
# download templates over the network during the demo.
RUN nuclei -update-templates 2>&1 | tail -3 || echo "[build] nuclei template update skipped"

WORKDIR /app

# Install a CPU-only torch BEFORE requirements.txt so sentence-transformers' dependency
# resolution finds torch already satisfied and never touches PyPI's default Linux wheel
# (CUDA-bundled, ~530MB+ plus several hundred MB of nvidia-* libraries). Installing CPU
# torch first avoids downloading torch twice and is the single biggest size/time cut in
# this build — we only ever embed on CPU.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# sqlmap is installed via pip (see requirements.txt) and exposes a `sqlmap`
# console entrypoint on PATH — no bundled script needed.
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the Select-phase embedding model so the first scan doesn't fetch it over
# the network. Cached under /root/.cache/huggingface inside the image.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')" \
    || echo "[build] embedding model pre-download skipped"

# Copy server package (agent/ is already a sub-directory of server/).
COPY server/ .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
