#!/bin/bash

# Exit on error
set -e

echo "======================================"
echo "    Master Setup Script"
echo "======================================"

echo "[1/4] Setting up virtual environment..."
rm -rf venv
python3 -m venv venv
source venv/bin/activate

echo "[2/4] Installing Python dependencies..."
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    echo "Warning: requirements.txt not found!"
fi

echo "[3/4] Installing Playwright driver locally..."
# This fixes the large driver issue by installing it safely inside the local cache
playwright install --with-deps

echo "[4/4] Setting up local Go binaries in ./bin..."
mkdir -p bin

# Check if unzip is installed
if ! command -v unzip &> /dev/null; then
    echo "Error: 'unzip' is not installed. Please install unzip to automatically extract binaries."
    exit 1
fi

TOOLS=("subfinder" "katana" "nuclei" "httpx")

for tool in "${TOOLS[@]}"; do
    if [ ! -f "bin/$tool" ]; then
        echo " -> Downloading $tool..."
        # Get latest release version dynamically
        latest_url=$(curl -Ls -o /dev/null -w %{url_effective} "https://github.com/projectdiscovery/$tool/releases/latest")
        version=$(basename "$latest_url" | sed 's/v//')
        
        # Download and extract binary
        curl -L -o "$tool.zip" -s "https://github.com/projectdiscovery/$tool/releases/download/v${version}/${tool}_${version}_linux_amd64.zip"
        unzip -q "$tool.zip" "$tool" -d bin/
        rm "$tool.zip"
        chmod +x "bin/$tool"
    else
        echo " -> $tool already exists in bin/, skipping."
    fi
done

echo "======================================"
echo " Setup Complete!"
echo " Activate environment using: source venv/bin/activate"
echo " Run scan using: python3 main.py -u https://target.com"
echo "======================================"
