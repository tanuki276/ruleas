#!/bin/sh
# Run with an authenticated repository administrator's GitHub CLI.
set -eu
cd "$(dirname "$0")/.."
gh api --method PUT repos/tanuki276/ruleas/branches/main/protection \
  --input .github/branch-protection.json
