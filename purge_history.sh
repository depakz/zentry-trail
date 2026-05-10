#!/bin/bash

# Exit on error
set -e

echo "Starting deep-clean of git history to remove large binaries..."
echo "This may take a moment depending on the size of your repository history."

# Force Git to forget these specific files existed in any previous commit
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch bin/katana bin/nuclei venv/lib/python3.12/site-packages/playwright/driver/node" \
  --prune-empty --tag-name-filter cat -- --all

echo ""
echo "History purged successfully!"
echo "Please verify your files are still intact locally. The large files should be removed from git tracking but kept on your disk."
echo ""
echo "Next steps:"
echo "1. git add .gitignore"
echo "2. git commit -m \"chore: professionalize repo structure and purge large binaries\""
echo "3. git push origin main --force"
