#!/bin/bash

# Exit on error, but allow specific git rm commands to fail if files are already untracked
set -e

echo "Removing venv/ directory from git index (keeping local files)..."
git rm -r --cached venv/ || echo "venv/ was not fully tracked or already removed."

echo "Removing specific large files from git index..."
git rm --cached venv/lib/python3.12/site-packages/playwright/driver/node || echo "Playwright node binary already untracked."
git rm --cached bin/katana || echo "bin/katana already untracked."
git rm --cached bin/nuclei || echo "bin/nuclei already untracked."

echo "Adding entries to .gitignore..."
# Append to .gitignore, creating it if it doesn't exist
{
    echo ""
    echo "# Python Virtual Environment"
    echo "venv/"
    echo ""
    echo "# Python Cache"
    echo "__pycache__/"
    echo ""
    echo "# Binaries"
    echo "bin/"
} >> .gitignore

echo "Done! Run 'git status' to verify."
echo "Next step: commit these changes using 'git commit -m \"Fix tracking of large binaries and venv\"'"
