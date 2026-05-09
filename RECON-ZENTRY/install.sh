#!/bin/bash

echo "════════════════════════════════════════════════════════════"
echo "  🚀 HACK WITH YUVA v3.0 - Installation Script"
echo "════════════════════════════════════════════════════════════"

# Create virtual environment
echo -e "\n[1/4] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "\n[2/4] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check tools
echo -e "\n[3/4] Checking required tools..."

TOOLS=(
    "subfinder:github.com/projectdiscovery/subfinder"
    "httpx:github.com/projectdiscovery/httpx"
    "katana:github.com/projectdiscovery/katana"
    "nuclei:github.com/projectdiscovery/nuclei"
    "gau:github.com/lc/gau"
    "curl:Man page: curl"
    "jq:github.com/jqlang/jq"
)

for tool_info in "${TOOLS[@]}"; do
    TOOL="${tool_info%%:*}"
    SOURCE="${tool_info#*:}"
    
    if command -v $TOOL &> /dev/null; then
        echo "   ✅ $TOOL"
    else
        echo "   ⚠️  $TOOL not found - install from: $SOURCE"
    fi
done

# Create directories
echo -e "\n[4/4] Creating directories..."
mkdir -p data/sessions reports output logs

echo -e "\n════════════════════════════════════════════════════════════"
echo "  ✅ Installation complete!"
echo "  📖 Usage: python main.py"
echo "════════════════════════════════════════════════════════════"
