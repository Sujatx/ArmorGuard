#!/usr/bin/env bash
# ArmorGuard — Security Tool Installer (Linux / macOS)
# Run from the repo root: bash scripts/install_tools.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS_DIR="$REPO_ROOT/tools"
ENV_FILE="$REPO_ROOT/server/.env"
mkdir -p "$TOOLS_DIR"

set_env_var() {
    local key="$1" value="$2"
    if [ -f "$ENV_FILE" ]; then
        if grep -q "^$key=" "$ENV_FILE"; then
            sed -i.bak "s|^$key=.*|$key=$value|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
        else
            echo "$key=$value" >> "$ENV_FILE"
        fi
    fi
}

OS="$(uname -s)"
ARCH="$(uname -m)"
PD_OS="linux"; PD_ARCH="amd64"
[ "$OS" = "Darwin" ] && PD_OS="darwin"
[ "$ARCH" = "arm64" ] && PD_ARCH="arm64"

# ── nmap ──────────────────────────────────────────────────────────────────────
echo "=== nmap ==="
if command -v nmap &>/dev/null; then
    echo "nmap already installed: $(command -v nmap)"
elif [ "$OS" = "Darwin" ]; then
    brew install nmap
elif command -v apt-get &>/dev/null; then
    sudo apt-get install -y nmap
elif command -v yum &>/dev/null; then
    sudo yum install -y nmap
fi
set_env_var "NMAP_PATH" "nmap"

# ── nuclei ────────────────────────────────────────────────────────────────────
echo "=== nuclei ==="
if [ -f "$TOOLS_DIR/nuclei" ]; then
    echo "nuclei already present"
else
    URL=$(curl -s "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" \
        | grep "browser_download_url" | grep "${PD_OS}_${PD_ARCH}.zip" | head -1 | cut -d'"' -f4)
    curl -sL "$URL" -o "$TOOLS_DIR/nuclei.zip"
    unzip -q "$TOOLS_DIR/nuclei.zip" -d "$TOOLS_DIR/nuclei_tmp"
    mv "$TOOLS_DIR/nuclei_tmp/nuclei" "$TOOLS_DIR/nuclei"
    chmod +x "$TOOLS_DIR/nuclei"
    rm -rf "$TOOLS_DIR/nuclei.zip" "$TOOLS_DIR/nuclei_tmp"
    echo "nuclei installed → $TOOLS_DIR/nuclei"
fi
set_env_var "NUCLEI_PATH" "$TOOLS_DIR/nuclei"

# ── httpx (ProjectDiscovery) ──────────────────────────────────────────────────
echo "=== httpx (ProjectDiscovery) ==="
if [ -f "$TOOLS_DIR/httpx" ]; then
    echo "httpx already present"
else
    URL=$(curl -s "https://api.github.com/repos/projectdiscovery/httpx/releases/latest" \
        | grep "browser_download_url" | grep "${PD_OS}_${PD_ARCH}.zip" | head -1 | cut -d'"' -f4)
    curl -sL "$URL" -o "$TOOLS_DIR/httpx.zip"
    unzip -q "$TOOLS_DIR/httpx.zip" -d "$TOOLS_DIR/httpx_tmp"
    mv "$TOOLS_DIR/httpx_tmp/httpx" "$TOOLS_DIR/httpx"
    chmod +x "$TOOLS_DIR/httpx"
    rm -rf "$TOOLS_DIR/httpx.zip" "$TOOLS_DIR/httpx_tmp"
    echo "httpx installed → $TOOLS_DIR/httpx"
fi
set_env_var "HTTPX_PATH" "$TOOLS_DIR/httpx"

# ── katana (ProjectDiscovery crawler — discovery stage) ───────────────────────
echo "=== katana ==="
if [ -f "$TOOLS_DIR/katana" ]; then
    echo "katana already present"
else
    URL=$(curl -s "https://api.github.com/repos/projectdiscovery/katana/releases/latest" \
        | grep "browser_download_url" | grep "${PD_OS}_${PD_ARCH}.zip" | head -1 | cut -d'"' -f4)
    curl -sL "$URL" -o "$TOOLS_DIR/katana.zip"
    unzip -q "$TOOLS_DIR/katana.zip" -d "$TOOLS_DIR/katana_tmp"
    mv "$TOOLS_DIR/katana_tmp/katana" "$TOOLS_DIR/katana"
    chmod +x "$TOOLS_DIR/katana"
    rm -rf "$TOOLS_DIR/katana.zip" "$TOOLS_DIR/katana_tmp"
    echo "katana installed → $TOOLS_DIR/katana"
fi
set_env_var "KATANA_PATH" "$TOOLS_DIR/katana"

# ── ffuf (route brute-forcer — discovery) ─────────────────────────────────────
echo "=== ffuf ==="
if [ -f "$TOOLS_DIR/ffuf" ]; then
    echo "ffuf already present"
else
    URL=$(curl -s "https://api.github.com/repos/ffuf/ffuf/releases/latest" \
        | grep "browser_download_url" | grep "${PD_OS}_${PD_ARCH}.tar.gz" | head -1 | cut -d'"' -f4)
    curl -sL "$URL" -o "$TOOLS_DIR/ffuf.tar.gz"
    tar -xzf "$TOOLS_DIR/ffuf.tar.gz" -C "$TOOLS_DIR" ffuf
    chmod +x "$TOOLS_DIR/ffuf"
    rm -f "$TOOLS_DIR/ffuf.tar.gz"
    echo "ffuf installed → $TOOLS_DIR/ffuf"
fi
set_env_var "FFUF_PATH" "$TOOLS_DIR/ffuf"

# ── nikto (web server scanner) ────────────────────────────────────────────────
echo "=== nikto ==="
if command -v nikto &>/dev/null; then
    echo "nikto already installed: $(command -v nikto)"
elif [ "$OS" = "Darwin" ]; then
    brew install nikto
elif command -v apt-get &>/dev/null; then
    sudo apt-get install -y nikto || echo "nikto not in apt — install from https://github.com/sullo/nikto"
fi
set_env_var "NIKTO_PATH" "nikto"
# ffuf wordlist: use the repo-bundled list (always present), matching the backend image.
set_env_var "FFUF_WORDLIST" "$REPO_ROOT/scripts/wordlists/common.txt"

# ── sqlmap + arjun ────────────────────────────────────────────────────────────
# Installed via pip — expose `sqlmap` / `arjun` console entrypoints on PATH
# (matches the backend image, which installs them the same way).
echo "=== sqlmap + arjun ==="
if command -v sqlmap &>/dev/null; then
    echo "sqlmap already installed: $(command -v sqlmap)"
else
    pip install --quiet --upgrade sqlmap || python3 -m pip install --quiet --upgrade sqlmap
fi
pip install --quiet --upgrade arjun || python3 -m pip install --quiet --upgrade arjun
set_env_var "SQLMAP_PATH" "sqlmap"
set_env_var "ARJUN_PATH" "arjun"

# ── nuclei templates ──────────────────────────────────────────────────────────
echo "=== nuclei templates ==="
"$TOOLS_DIR/nuclei" -update-templates 2>&1 | tail -3

echo ""
echo "All tools installed (nmap, nuclei, httpx, sqlmap). Paths written to backend/.env"
