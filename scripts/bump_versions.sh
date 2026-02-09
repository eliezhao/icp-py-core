#!/usr/bin/env bash
# Bump both icp-py-core and ic-candid-parser versions so the release workflow
# publishes the correct extension version (avoids updating only the main package).
#
# Usage:
#   ./scripts/bump_versions.sh <new_main_version> [extension_version]
#
# Examples:
#   ./scripts/bump_versions.sh 2.3.0
#     -> main version = "2.3.0", extension patch+1 (e.g. 0.1.2 -> 0.1.3),
#        main dependency ic_candid_parser>=<new_extension_version>
#
#   ./scripts/bump_versions.sh 2.3.0 0.1.5
#     -> main 2.3.0, extension 0.1.5, dependency ic_candid_parser>=0.1.5
#
# Then commit and tag, e.g.: git tag v2.3.0

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIN_PYPROJECT="$REPO_ROOT/pyproject.toml"
CARGO_TOML="$REPO_ROOT/src/icp_candid/ic_candid_parser/Cargo.toml"

usage() {
    echo "Usage: $0 <main_version> [extension_version]"
    echo "  main_version      e.g. 2.3.0"
    echo "  extension_version optional, e.g. 0.1.3 (default: auto bump patch from Cargo.toml)"
    exit 1
}

if [ -z "$1" ]; then
    usage
fi
NEW_MAIN="$1"

# Read current extension version and bump patch
current_ext() {
    grep '^version = ' "$CARGO_TOML" | sed -n 's/^version = "\(.*\)"$/\1/p'
}
bump_patch() {
    local v="$1"
    local major_minor="${v%.*}"
    local patch="${v##*.}"
    echo "${major_minor}.$((patch + 1))"
}

if [ -n "$2" ]; then
    NEW_EXT="$2"
else
    CURRENT_EXT="$(current_ext)"
    NEW_EXT="$(bump_patch "$CURRENT_EXT")"
    echo "Extension version not given; bumping $CURRENT_EXT -> $NEW_EXT"
fi

echo "Will set: icp-py-core=$NEW_MAIN, ic-candid-parser=$NEW_EXT"
echo ""

# Update main package version
sed -i.bak "s/^version = \".*\"$/version = \"$NEW_MAIN\"/" "$MAIN_PYPROJECT"
rm -f "$MAIN_PYPROJECT.bak"

# Update main package dependency on extension
sed -i.bak "s/\"ic_candid_parser>=[^\"]*\"/\"ic_candid_parser>=$NEW_EXT\"/" "$MAIN_PYPROJECT"
rm -f "$MAIN_PYPROJECT.bak"

# Update extension version (first "version =" in Cargo.toml, under [package]; awk for macOS)
awk -v newver="$NEW_EXT" '/^version = / && !done { sub(/version = ".*"/, "version = \"" newver "\""); done=1 } 1' "$CARGO_TOML" > "$CARGO_TOML.tmp" && mv "$CARGO_TOML.tmp" "$CARGO_TOML"

echo "Done. Updated:"
echo "  $MAIN_PYPROJECT  -> version = \"$NEW_MAIN\", ic_candid_parser>=$NEW_EXT"
echo "  $CARGO_TOML      -> version = \"$NEW_EXT\""
echo ""
echo "Next: commit and tag, e.g.  git add -A && git commit -m 'chore: release v$NEW_MAIN' && git tag v$NEW_MAIN"
echo "Then push tag to trigger release workflow."
