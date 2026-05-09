#!/bin/bash

set -e

echo "[*] Starting Security Pipeline setup..."

# =========================
# 1. System dependencies
# =========================
echo "[*] Installing system tools..."
sudo apt-get update
sudo apt-get install -y nmap sqlmap unzip wget curl jq

# =========================
# 2. Create bin directory
# =========================
BIN_DIR="$(pwd)/bin"
mkdir -p "$BIN_DIR"

echo "[*] Using bin directory: $BIN_DIR"

# =========================
# Helper: install binary safely
# =========================
install_binary() {
    local name=$1
    local url=$2
    local binary_name=$3
    local extract_dir=$4

    echo "[*] Installing $name..."

    if [ -f "$BIN_DIR/$binary_name" ]; then
        echo "[*] $name already exists → skipping"
        return
    fi

    # Download archive
    if [[ "$url" == *.zip ]]; then
        tmpfile="temp.zip"
        curl -L -o "$tmpfile" "$url"
        unzip -o "$tmpfile" > /dev/null
    elif [[ "$url" == *.tar.gz ]] || [[ "$url" == *.tgz ]]; then
        tmpfile="temp.tar.gz"
        curl -L -o "$tmpfile" "$url"
        tar -xzf "$tmpfile"
    else
        tmpfile="temp.bin"
        curl -L -o "$tmpfile" "$url"
    fi

    if [ -n "$extract_dir" ]; then
        BIN_PATH=$(find "$extract_dir" -type f -name "$binary_name" | head -n 1)
        rm -rf "$extract_dir"
    else
        # try to find the binary in current dir if archive extracted
        BIN_PATH=$(find . -maxdepth 2 -type f -name "$binary_name" | head -n 1)
        if [ -z "$BIN_PATH" ] && [ -f "$tmpfile" ]; then
            BIN_PATH="$tmpfile"
        fi
    fi

    if [ -z "$BIN_PATH" ] || [ ! -f "$BIN_PATH" ]; then
        echo "[!] Failed to locate $name binary"
        rm -f "$tmpfile" || true
        return 1
    fi

    install -m 755 "$BIN_PATH" "$BIN_DIR/$binary_name"
    rm -f "$tmpfile" || true
}

# =========================
# 3. Nuclei
# =========================
install_binary \
"nuclei" \
"https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.8.0_linux_amd64.zip" \
"nuclei" \
""

# =========================
# 4. HTTPX
# =========================
install_binary \
"httpx" \
"https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.9.0_linux_amd64.zip" \
"httpx" \
""

# =========================
# 5. Gospider
# =========================
install_binary \
"gospider" \
"https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_linux_x86_64.zip" \
"gospider" \
"gospider_v1.1.6_linux_x86_64"

# =========================
# subfinder (projectdiscovery)
# =========================
install_binary \
"subfinder" \
"https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.14.0_linux_amd64.zip" \
"subfinder" \
""

# =========================
# gau (github.com/lc/gau)
# =========================
install_binary \
"gau" \
"https://github.com/lc/gau/releases/latest/download/gau_2.2.4_linux_amd64.tar.gz" \
"gau" \
""

# =========================
# katana (projectdiscovery)
# =========================
install_binary \
"katana" \
"https://github.com/projectdiscovery/katana/releases/latest/download/katana_1.6.1_linux_amd64.zip" \
"katana" \
""

# =========================
# ffuf (fuzz faster u fool)
# =========================
install_binary \
"ffuf" \
"https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz" \
"ffuf" \
""

# =========================
# dalfox (xss scanner)
# =========================
install_binary \
"dalfox" \
"https://github.com/hahwul/dalfox/releases/latest/download/dalfox-linux-amd64.tar.gz" \
"dalfox" \
""

# =========================
# Python tools: arjun, paramspider
# Install to user site to avoid sudo
# =========================
echo "[*] Installing Python tools: arjun, paramspider"
python3 -m pip install --user arjun paramspider || true

# =========================
# 6. Permissions
# =========================
chmod +x "$BIN_DIR"/*

# =========================
# 7. PATH handling (safe)
# =========================
if ! grep -q "$BIN_DIR" ~/.bashrc; then
    echo "export PATH=\$PATH:$BIN_DIR" >> ~/.bashrc
fi

export PATH=$PATH:$BIN_DIR

echo "[*] Setup complete!"
echo "[*] Installed tools:"
echo "    nmap, sqlmap (system)"
echo "    nuclei, httpx, gospider, subfinder, katana, gau, ffuf, dalfox (bin)"
echo "    arjun, paramspider (python user installs)"