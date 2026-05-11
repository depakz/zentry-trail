#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
BIN_DIR="$ROOT_DIR/bin"

log() {
    printf '%s\n' "$1"
}

download_pd_binary() {
    local tool="$1"
    local tmp_zip="$ROOT_DIR/.${tool}.zip"
    local latest_tag
    latest_tag="$(curl -fsSL "https://api.github.com/repos/projectdiscovery/${tool}/releases/latest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')"
    local asset="${tool}_${latest_tag}_linux_amd64.zip"
    local url="https://github.com/projectdiscovery/${tool}/releases/download/v${latest_tag}/${asset}"

    log " -> Downloading ${tool} ${latest_tag}"
    curl -fsSL "$url" -o "$tmp_zip"
    python3 -m zipfile -e "$tmp_zip" "$BIN_DIR"
    rm -f "$tmp_zip"
    chmod +x "$BIN_DIR/${tool}"
}

log "======================================"
log "    Master Setup Script"
log "======================================"

log "[1/4] Creating virtual environment"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

log "[2/4] Installing Python dependencies"
pip install --upgrade pip setuptools wheel >/dev/null
pip install -r "$ROOT_DIR/requirements.txt"

log "[3/4] Installing Playwright runtime"
playwright install --with-deps

log "[4/4] Installing external binaries in ./bin"
mkdir -p "$BIN_DIR"
for tool in nuclei subfinder katana; do
    if [[ -x "$BIN_DIR/$tool" ]]; then
        log " -> ${tool} already present"
    else
        download_pd_binary "$tool"
    fi
done

log "======================================"
log " Setup Complete"
log " Activate using: source .venv/bin/activate"
log " Run scan: python3 main.py -u https://target.com"
log "======================================"
