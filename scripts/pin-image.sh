#!/usr/bin/env bash
# Pins action.yml (runs.image) to the image the release workflow just pushed.
#   scripts/pin-image.sh sha256:<digest> <version>
# The name comes from IMAGE_NAME in .github/workflows/release.yml, so it only has to be changed there.
set -euo pipefail
cd "$(dirname "$0")/.."
digest="${1:-}"
version="${2:-}"
if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then echo "usage: $0 sha256:<64 hex digest> <version>" >&2; exit 2; fi
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then echo "usage: $0 sha256:<digest> <version like 1.1.0>" >&2; exit 2; fi
name="$(sed -n 's/^ *IMAGE_NAME: *//p' .github/workflows/release.yml | head -1 | sed 's/ *#.*//')"
[ -n "$name" ] || { echo "IMAGE_NAME not found in release.yml" >&2; exit 1; }
tmp="$(mktemp)"
awk -v img="  image: docker://${name}@${digest}" -v ver="  # ${version}" '
  /^  # [0-9]+\.[0-9]+\.[0-9]+/ || /^  # TODO\(release\)/ { next }
  /^  image: / { print ver; print img; next }
  { print }' action.yml > "$tmp"
mv "$tmp" action.yml
grep -n "image:" action.yml
