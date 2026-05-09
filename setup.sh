#!/usr/bin/env bash
set -euo pipefail

show_help() {
  cat <<EOF
Usage: $0 [--venv DIR] [--system] [--run-scripts] [--help]

Options:
  --venv DIR       Virtualenv directory to create/use (default: .venv)
  --system         Install optional system packages via apt (requires sudo)
  --run-scripts    Run existing project install scripts (RECON-ZENTRY/install.sh and security_pipeline/setup.sh). Default: enabled
  --help           Show this help
EOF
}

VENV_DIR=".venv"
INSTALL_SYSTEM=0
RUN_SCRIPTS=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv)
      VENV_DIR="$2"
      shift 2
      ;;
    --system)
      INSTALL_SYSTEM=1
      shift
      ;;
    --run-scripts)
      RUN_SCRIPTS=1
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

echo "[*] Using venv directory: $VENV_DIR"

if [[ $INSTALL_SYSTEM -eq 1 ]]; then
  if command -v apt-get &> /dev/null; then
    echo "[*] Installing system packages (sudo will be used)..."
    sudo apt-get update
    sudo apt-get install -y nmap sqlmap unzip wget curl jq build-essential
  else
    echo "[!] Apt not found — skipping system package installation"
  fi
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "[*] Creating virtual environment: $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "[*] Upgrading pip and wheel..."
pip install --upgrade pip setuptools wheel

REQ_FILES=(
  "RECON-ZENTRY/requirements.txt"
  "RECON-ZENTRY/patches/requirements_additions.txt"
  "security_pipeline/requirements.txt"
)

for f in "${REQ_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    echo "[*] Installing packages from $f"
    pip install -r "$f"
  else
    echo "[*] Not found: $f — skipping"
  fi
done

echo "[*] Installing top-level extras (if any)"
if [[ -f "requirements.txt" ]]; then
  pip install -r requirements.txt || true
fi

if [[ $RUN_SCRIPTS -eq 1 ]]; then
  if [[ -f "RECON-ZENTRY/install.sh" ]]; then
    echo "[*] Running RECON-ZENTRY/install.sh"
    (cd RECON-ZENTRY && bash install.sh)
  else
    echo "[*] RECON-ZENTRY/install.sh not found — skipping"
  fi

  if [[ -f "security_pipeline/setup.sh" ]]; then
    echo "[*] Running security_pipeline/setup.sh"
    (cd security_pipeline && bash setup.sh)
  else
    echo "[*] security_pipeline/setup.sh not found — skipping"
  fi
fi

echo "\n════════════════════════════════════════════════════════════"
echo "  ✅ Setup complete. Activate the venv with: source $VENV_DIR/bin/activate"
echo "════════════════════════════════════════════════════════════"

exit 0
