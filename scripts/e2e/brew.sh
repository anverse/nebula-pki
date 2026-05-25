#!/usr/bin/env bash
# End-to-end install test for the Homebrew tap.
#
# Runs an isolated Homebrew-on-Linux container, taps anverse/nebula-pki,
# installs the formula from the latest released tag, and exercises the CLI.
#
# CONTAINER_RUNTIME must be set by the caller (the taskfile sets it).
# Examples: docker, nerdctl, podman.

set -euo pipefail

: "${CONTAINER_RUNTIME:?CONTAINER_RUNTIME must be set (e.g. docker, nerdctl, podman)}"
IMAGE="homebrew/brew:latest"
TAP="anverse/nebula-pki"
FORMULA="anverse/nebula-pki/nebula-pki"

if ! command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1; then
  echo "error: container runtime '$CONTAINER_RUNTIME' not on PATH" >&2
  exit 2
fi

echo "==> brew e2e: runtime=$CONTAINER_RUNTIME image=$IMAGE"

"$CONTAINER_RUNTIME" run --rm -i "$IMAGE" bash -eu -o pipefail <<EOF
echo "==> tapping $TAP"
brew tap $TAP https://github.com/$TAP.git

echo "==> installing $FORMULA"
brew install $FORMULA

echo "==> nebula-pki --version"
out=\$(nebula-pki --version)
echo "got: \$out"

# Expect three space-separated tokens: <version> <commit> <date>
echo "\$out" | grep -Eq '^[^ ]+ [^ ]+ [^ ]+$' || {
  echo "error: --version output did not match expected format" >&2
  exit 1
}

echo "==> nebula-pki version (subcommand)"
nebula-pki version
EOF

echo "==> brew e2e: ok"
