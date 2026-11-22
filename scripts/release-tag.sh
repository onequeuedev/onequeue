#!/usr/bin/env bash
# Tags a release and moves the major tag.
#
#   scripts/release-tag.sh 1.1.0 [commit]      (commit defaults to HEAD)
#
# Creates vX.Y.Z at the commit and force-moves vX (the "major tag", for example v1) to the same commit, so workflows that use
# onequeuedev/onequeue@v1 pick up every 1.x release by themselves. Breaking changes are released as 2.0.0 and move v2 instead.
# A pre-release (1.2.0-rc.1) only gets its own tag; the major tag is never moved to it.
#
# It asks for confirmation before it changes anything, and again before it pushes. The release tag vX.Y.Z is never moved: if it
# already exists the script stops. The major tag only ever moves forward.
set -euo pipefail

usage() { echo "usage: $0 <version like 1.1.0> [commit]" >&2; exit 2; }
version="${1:-}"
[[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.]+)?$ ]] || usage
major="${BASH_REMATCH[1]}"
prerelease="${BASH_REMATCH[4]:-}"
tag="v${version}"
major_tag="v${major}"

root="$(git rev-parse --show-toplevel)"
cd "$root"
commit="$(git rev-parse --verify "${2:-HEAD}^{commit}")"

die() { echo "error: $*" >&2; exit 1; }

[ -z "$(git status --porcelain)" ] || die "the working tree has uncommitted changes. Commit or stash them first."
git rev-parse -q --verify "refs/tags/${tag}" >/dev/null && die "${tag} already exists. A release tag is never moved; use the next version."

# The commit being released must pin the image this release built (see scripts/pin-image.sh), not the old or a placeholder one.
pinned="$(git show "${commit}:action.yml" | sed -n 's#^  image: docker://onequeuedev/onequeue@sha256:\([0-9a-f]\{64\}\)$#\1#p')"
if [ -z "$pinned" ] && [ -z "${ALLOW_UNPINNED:-}" ]; then
  die "action.yml at ${commit:0:7} does not pin docker://onequeuedev/onequeue@sha256:<digest>. Run scripts/pin-image.sh and commit it first."
fi

old_major=""
if [ -z "$prerelease" ]; then
  old_major="$(git rev-parse -q --verify "refs/tags/${major_tag}^{commit}" || true)"
  # The major tag only moves forward: the new version must be higher than every release already in this major.
  highest="$(git tag --list "v${major}.*" | grep -E "^v${major}\.[0-9]+\.[0-9]+$" | sed 's/^v//' | sort -V | tail -1 || true)"
  if [ -n "$highest" ] && [ "$(printf '%s\n%s\n' "$highest" "$version" | sort -V | tail -1)" != "$version" ]; then
    die "${version} is lower than ${highest}, which already exists. The major tag only moves forward."
  fi
fi

echo "Release ${version}"
echo "  commit:  ${commit:0:12}  $(git log -1 --format=%s "$commit")"
echo "  image:   ${pinned:+sha256:${pinned:0:19}…}${pinned:-(not pinned: ALLOW_UNPINNED)}"
echo "  will create tag ${tag}"
if [ -n "$prerelease" ]; then
  echo "  pre-release: ${major_tag} is not moved"
elif [ -n "$old_major" ]; then
  echo "  will MOVE ${major_tag} from ${old_major:0:12} to ${commit:0:12}  (everyone on @${major_tag} gets this release)"
else
  echo "  will create ${major_tag} at ${commit:0:12}  (everyone on @${major_tag} gets this release)"
fi
read -r -p "Type the version to confirm (${version}): " answer || answer=""
[ "$answer" = "$version" ] || die "not confirmed. Nothing was changed."

git tag -a "$tag" -m "OneQueue Scan ${version}" "$commit"
[ -n "$prerelease" ] || git tag -f -a "$major_tag" -m "OneQueue Scan ${major_tag}: latest ${major}.x release (${version})" "$commit" >/dev/null
echo "Tagged ${tag}${prerelease:+ (pre-release)}$([ -n "$prerelease" ] || echo " and ${major_tag}") at ${commit:0:12}."
echo "Pin this SHA in workflows that must not move:  $(git rev-parse "${tag}^{commit}")"

read -r -p "Push to origin now? [y/N] " push || push=""
if [ "$push" = "y" ] || [ "$push" = "Y" ]; then
  git push origin "refs/tags/${tag}"
  [ -n "$prerelease" ] || git push origin "+refs/tags/${major_tag}"
  echo "Pushed. Next: gh release create ${tag} --title \"OneQueue Scan ${version}\" --notes-file docs/release-notes-${version}.md"
else
  echo "Not pushed. When ready:"
  echo "  git push origin ${tag}"
  [ -n "$prerelease" ] || echo "  git push origin +${major_tag}      # force: the major tag moves"
fi
