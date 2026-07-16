#!/usr/bin/env bash
# End-to-end install test for the Nix flake.
#
# Runs an isolated nixos/nix container and executes the published flake
# from GitHub. No build artifacts persist on the host.
#
# CONTAINER_RUNTIME must be set by the caller (the taskfile sets it).
# Examples: docker, nerdctl, podman.

set -euo pipefail

: "${CONTAINER_RUNTIME:?CONTAINER_RUNTIME must be set (e.g. docker, nerdctl, podman)}"
IMAGE="nixpkgs/nix-flakes:latest"
FLAKE="github:anverse/nebula-pki"

if ! command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1; then
  echo "error: container runtime '$CONTAINER_RUNTIME' not on PATH" >&2
  exit 2
fi

echo "==> nix e2e: runtime=$CONTAINER_RUNTIME image=$IMAGE flake=$FLAKE"

"$CONTAINER_RUNTIME" run --rm -i "$IMAGE" sh -eu <<EOF
echo "==> nix run $FLAKE -- --version"
out=\$(nix run $FLAKE -- --version)
echo "got: \$out"

# Expect three space-separated tokens: <version> <commit> <date>
set -- \$out
if [ "\$#" -ne 3 ]; then
  echo "error: --version output did not match expected format (\$# tokens)" >&2
  exit 1
fi

echo "==> nix run $FLAKE -- version"
nix run $FLAKE -- version
EOF

echo "==> nix e2e: ok"
