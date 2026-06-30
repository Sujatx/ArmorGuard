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

# Single canonical scanner-binary location: /opt/tools, given PATH precedence below.
# IMPORTANT: the Python `httpx` library (pulled in by supabase/pydantic-ai) installs
# its own `httpx` console script into /usr/local/bin during pip install. Keeping the
# ProjectDiscovery `httpx` scanner in /opt/tools *ahead* of /usr/local/bin on PATH
# ensures `httpx` resolves to the scanner, not the Python lib's CLI.
# nuclei + httpx + katana (ProjectDiscovery) — pinned release binaries.
# katana is the discovery crawler: it maps the target's endpoints/parameters so the
# attack tools (nuclei, sqlmap) hit real routes instead of just the base URL.
RUN mkdir -p /opt/tools \
    && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /opt/tools/nuclei \
    && chmod +x /opt/tools/nuclei \
    && curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip -d /tmp/httpx \
    && mv /tmp/httpx/httpx /opt/tools/httpx \
    && chmod +x /opt/tools/httpx \
    && curl -sSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" -o /tmp/katana.zip \
    && unzip -q /tmp/katana.zip -d /tmp/katana \
    && mv /tmp/katana/katana /opt/tools/katana \
    && chmod +x /opt/tools/katana \
    && curl -sSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /opt/tools ffuf \
    && chmod +x /opt/tools/ffuf \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei /tmp/httpx.zip /tmp/httpx /tmp/katana.zip /tmp/katana /tmp/ffuf.tar.gz

# nikto — installed from source (not packaged in the slim image's apt repos). A small
# wrapper preserves nikto's program dir so it finds its config/plugins.
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto


# Bundled wordlist for ffuf route brute-forcing (includes multi-level API paths so it
# can discover endpoints like /api/products that a crawler never sees).
COPY scripts/wordlists/common.txt /opt/tools/wordlists/common.txt

# Put the scanner dir ahead of /usr/local/bin so the ProjectDiscovery httpx wins.
ENV PATH="/opt/tools:${PATH}"

# Ship the nuclei template DB inside the image so the first scan does not have to
# download templates over the network during the demo.
RUN nuclei -update-templates 2>&1 | tail -3 || echo "[build] nuclei template update skipped"

WORKDIR /app

# sqlmap is installed via pip (see requirements.txt) and exposes a `sqlmap`
# console entrypoint on PATH — no bundled script needed.
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server package (agent/ is already a sub-directory of server/).
COPY server/ .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
