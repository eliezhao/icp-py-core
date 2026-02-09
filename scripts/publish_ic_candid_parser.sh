#!/usr/bin/env bash
# Publish only ic-candid-parser (Rust extension) to PyPI as the latest version.
# Version is read from src/icp_candid/ic_candid_parser/Cargo.toml.
#
# Before running:
#   1. Set or confirm version in Cargo.toml (e.g. 0.1.2)
#   2. Install maturin: pip install maturin
#   3. Set PyPI credentials (e.g. TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-xxx)
#      or maturin will prompt for token
#
# This script builds and uploads only on the current machine (current platform + sdist).
# For full multi-platform wheels, use a GitHub Release: push a tag (e.g. v2.3.0) to
# trigger .github/workflows/release.yml, which builds and publishes both packages.

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARSER_DIR="$REPO_ROOT/src/icp_candid/ic_candid_parser"

cd "$PARSER_DIR"
echo "Building and publishing ic-candid-parser from: $PARSER_DIR"
echo "Version from Cargo.toml: $(grep '^version = ' Cargo.toml)"
echo ""

if ! command -v maturin &> /dev/null; then
    echo "Error: maturin not found. Install with: pip install maturin"
    exit 1
fi

maturin publish --release

echo ""
echo "Done. Check https://pypi.org/project/ic-candid-parser/ for the latest version."
