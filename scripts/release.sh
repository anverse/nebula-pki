#!/usr/bin/env bash
# Cut a release of nebula-pki.
#
# Bumps flake.nix to the requested version, re-pins vendorHash, verifies
# the flake builds, commits, tags, and pushes commit + tag atomically.
# The tag-push triggers .github/workflows/release.yml (GoReleaser).
#
# Usage:
#   scripts/release.sh vX.Y.Z
#
# Prerequisites:
#   - nix on PATH (provided by the dev shell from flake.nix)
#   - clean working tree on a branch tracking origin/main (or any branch
#     whose tip you want the tag to point at)
#   - permission to push to origin
#
# Rationale and the considered alternatives are in
# spec/adr/014-flake-version-sync.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly FLAKE_FILE="$REPO_ROOT/flake.nix"
# lib.fakeHash for sha256 — buildGoModule's well-known sentinel that
# triggers Nix to print the real hash in its error message.
readonly FAKE_HASH='sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: scripts/release.sh vX.Y.Z

  Bumps flake.nix, re-pins vendorHash, builds, commits, tags, pushes.
  See spec/adr/014-flake-version-sync.md.
EOF
  exit 2
}

# --- argument & environment checks -----------------------------------------

[[ $# -eq 1 ]] || usage

readonly TAG="$1"

# Require strict vX.Y.Z; rejects v1.0, 1.0.0, v1.0.0-rc1, etc. Loosen
# later when we actually need pre-release tags.
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || die "version must look like vX.Y.Z, got '$TAG'"

readonly VERSION="${TAG#v}"

cd "$REPO_ROOT"

command -v nix >/dev/null 2>&1 || die "nix not on PATH (try: nix develop)"
command -v git >/dev/null 2>&1 || die "git not on PATH"

# Working tree must be clean: bumping flake.nix on top of unrelated edits
# would entangle the release commit.
if ! git diff --quiet || ! git diff --cached --quiet; then
  die "working tree has uncommitted changes; commit or stash first"
fi

# Tag must not already exist locally or remotely.
if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
  die "tag $TAG already exists locally"
fi
if git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
  die "tag $TAG already exists on origin"
fi

# Anything we do is recoverable with `git reset --hard origin/<branch>`
# *until* we push. Surface that up front for the operator.
echo "==> releasing $TAG (flake version $VERSION)"
echo "    repo:   $REPO_ROOT"
echo "    branch: $(git rev-parse --abbrev-ref HEAD)"
echo "    head:   $(git rev-parse --short HEAD)"

# --- bump flake.nix --------------------------------------------------------

# Match a line of the form `          version = "0.0.1";`. The leading
# whitespace and quoting style in flake.nix is stable; we keep the regex
# narrow so we never mis-target a `version` field somewhere else (e.g.
# inside a meta block) if the file evolves.
if ! grep -qE '^[[:space:]]+version = "[^"]+";' "$FLAKE_FILE"; then
  die "no 'version = \"…\";' line in $FLAKE_FILE — has the schema changed?"
fi

current_version="$(sed -nE 's/^[[:space:]]+version = "([^"]+)";.*/\1/p' "$FLAKE_FILE" | head -n1)"
echo "==> bumping flake version: $current_version -> $VERSION"

# Cross-platform sed-in-place: write to a temp file and move.
tmp="$(mktemp)"
sed -E "s/^([[:space:]]+)version = \"[^\"]+\";/\\1version = \"$VERSION\";/" \
  "$FLAKE_FILE" > "$tmp"
mv "$tmp" "$FLAKE_FILE"

# --- re-pin vendorHash -----------------------------------------------------

# Replace the existing vendorHash with lib.fakeHash, run nix build, parse
# the "got: sha256-…" line that Nix prints on hash mismatch, write that
# back. When go.mod hasn't changed, the recovered hash equals the old
# one and the net diff is just the version bump.
echo "==> re-pinning vendorHash"

if ! grep -qE '^[[:space:]]+vendorHash = "[^"]+";' "$FLAKE_FILE"; then
  die "no 'vendorHash = \"…\";' line in $FLAKE_FILE"
fi

old_hash="$(sed -nE 's/^[[:space:]]+vendorHash = "([^"]+)";.*/\1/p' "$FLAKE_FILE" | head -n1)"

tmp="$(mktemp)"
sed -E "s|^([[:space:]]+)vendorHash = \"[^\"]+\";|\\1vendorHash = \"$FAKE_HASH\";|" \
  "$FLAKE_FILE" > "$tmp"
mv "$tmp" "$FLAKE_FILE"

# nix build is expected to fail here. Capture stderr; success would mean
# the fake-hash dance didn't take effect and we have nothing to parse.
build_log="$(mktemp)"
trap 'rm -f "$build_log"' EXIT

if nix build .#default --no-link --print-build-logs >"$build_log" 2>&1; then
  die "nix build succeeded with fake vendorHash — refusing to continue (flake.nix change didn't take effect?)"
fi

# Nix prints either:
#   got:    sha256-XXXX...
# or, in some flake-checker modes:
#   specified: sha256-AAAA...
#        got: sha256-XXXX...
# We grab the first sha256-… that follows a literal "got:" line.
new_hash="$(grep -E 'got:[[:space:]]+sha256-' "$build_log" \
            | head -n1 \
            | sed -E 's/.*got:[[:space:]]+(sha256-[A-Za-z0-9+/=]+).*/\1/')"

if [[ -z "$new_hash" ]]; then
  echo "----- nix build output -----" >&2
  cat "$build_log" >&2
  echo "----------------------------" >&2
  die "could not parse vendorHash from nix build output (see above)"
fi

echo "    old: $old_hash"
echo "    new: $new_hash"

tmp="$(mktemp)"
sed -E "s|^([[:space:]]+)vendorHash = \"[^\"]+\";|\\1vendorHash = \"$new_hash\";|" \
  "$FLAKE_FILE" > "$tmp"
mv "$tmp" "$FLAKE_FILE"

# --- verify the bumped flake builds ----------------------------------------

echo "==> verifying nix build .#default"
nix build .#default --no-link --print-build-logs

# --- commit, tag, push -----------------------------------------------------

# If somehow nothing changed (impossible given the version bump above,
# but defensive), bail rather than create an empty commit.
if git diff --quiet -- "$FLAKE_FILE"; then
  die "no changes to commit — did the version already match?"
fi

echo "==> committing"
git add "$FLAKE_FILE"
git commit -m "release $TAG"

echo "==> tagging $TAG"
git tag --annotate "$TAG" --message "$TAG"

echo "==> pushing commit + tag atomically"
branch="$(git rev-parse --abbrev-ref HEAD)"
git push --atomic origin "$branch" "$TAG"

cat <<EOF

==> released $TAG

The tag-push has triggered .github/workflows/release.yml. Watch:
  https://github.com/anverse/nebula-pki/actions

GoReleaser will publish the GitHub release, build archives, and commit
an updated Formula/nebula-pki.rb on top of the bump commit you just
pushed.
EOF
