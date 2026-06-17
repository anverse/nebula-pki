# Development

How to build, run, and test `nebula-pki` locally.

## Prerequisites

Choose one of:

- **Nix flake (recommended).** Provides Go, Task, and GoReleaser at pinned versions:

  ```sh
  nix develop
  ```

  Or with [direnv](https://direnv.net/): `echo "use flake" > .envrc && direnv allow`.

- **Manual.** Install Go (see `flake.nix` for the current version), plus
  [go-task](https://taskfile.dev) and optionally
  [goreleaser](https://goreleaser.com) if you want to exercise the release pipeline.

## Common tasks

```sh
task build          # build into bin/nebula-pki
task test           # unit tests
task test:e2e       # end-to-end testscript suite (depends on build)
task lint           # go vet + gofmt
task release:snapshot   # local goreleaser dry-run (no publish)
task nix:build      # build via the nix flake
task nix:run        # nix-built binary, prints --version
```

For a real release, see [Releasing](#releasing) below.

Run the binary directly:

```sh
./bin/nebula-pki --version
./bin/nebula-pki -c examples/homelab/nebula.hcl check
```

## Running latest code without installation

If you want to test your changes against example configs without installing or leaving build artifacts in your workspace:

### Option 1: `nix run` (recommended)

```sh
# Run from your local working directory against an example
nix run . -- -c examples/homelab/nebula.hcl --dry-run

# Check syntax only
nix run . -- -c examples/homelab/nebula.hcl check

# Full reconcile (writes to out/)
nix run . -- -c examples/homelab/nebula.hcl
```

The `.` tells Nix to build from your current code. The binary goes into `/nix/store`; nothing pollutes your workspace. Rebuilds automatically when you change Go sources.

### Option 2: Build once, reuse the binary

```sh
# Build via Nix (creates ./result symlink)
nix build
./result/bin/nebula-pki -c examples/homelab/nebula.hcl --dry-run

# Or copy to a temporary location
cp result/bin/nebula-pki /tmp/nebula-pki-test
/tmp/nebula-pki-test -c examples/homelab/nebula.hcl
```

### Option 3: Traditional Go build

```sh
go build -o /tmp/nebula-pki ./cmd/nebula-pki
/tmp/nebula-pki -c examples/homelab/nebula.hcl --dry-run
```

Pick `nix run .` if you're iterating on code and want the latest build every time with zero manual steps.

## Two build paths (intentional)

The repo carries **two** sets of build instructions:

1. **`.goreleaser.yaml`** — produces release archives (linux/darwin × amd64/arm64),
   checksums, and regenerates `Formula/nebula-pki.rb`. Used by the `release`
   GitHub workflow on tag push.
2. **`flake.nix`** — produces a reproducible Nix package and provides the dev
   shell. Used by `nix profile install`, `nix run`, and the `nix-build` CI job.

The build flags (`-trimpath`, `-ldflags`) are duplicated between the two. This
is deliberate: each tool needs its own native description and there is no
clean shared format. When changing ldflags or build settings, update **both**.

## Releasing

Cutting a release is one command:

```sh
task release VERSION=v0.1.0
```

That target runs [`scripts/release.sh`](./scripts/release.sh), which:

1. Bumps the `version` attribute in [`flake.nix`](./flake.nix) to the
   bare semver (`0.1.0`).
2. Re-pins `vendorHash` by running `nix build` against `lib.fakeHash`
   and parsing the recovered hash from the failure message. When
   `go.mod` hasn't changed, the hash comes back identical and the net
   diff is just the version bump.
3. Verifies the bumped flake builds (`nix build .#default`).
4. Commits the change as `release v0.1.0`.
5. Creates an annotated tag and pushes the commit + tag atomically.

The tag-push triggers [`.github/workflows/release.yml`](./.github/workflows/release.yml),
which runs GoReleaser to build archives, publish the GitHub release,
and commit a regenerated `Formula/nebula-pki.rb` on top of the bump
commit.

The script refuses to run on a dirty working tree, on an existing tag,
or with a malformed version. If anything fails before the `git push`,
recovery is `git reset --hard origin/<branch>` — nothing is published
until the tag reaches `origin`.

Tags use the `v` prefix because Go modules require it (`go install
…@v0.1.0` only resolves when the underlying tag is `v0.1.0`).
GoReleaser, Homebrew, and GitHub release UIs follow the same
convention. Strip the prefix in scripts with `${TAG#v}` when you need
a bare semver.

Why one command instead of `git tag && git push`: see
[ADR-014](./spec/adr/014-flake-version-sync.md). In short, the flake's
embedded `version` string would otherwise lag the tag by one commit,
making `nix run github:anverse/nebula-pki/vX.Y.Z -- --version` report
the previous version.

## Repository layout

```
cmd/nebula-pki/       # main entry point
internal/             # implementation packages
test/e2e/             # testscript-based end-to-end tests
examples/             # runnable example configurations
spec/                 # authoritative specification + ADRs
Formula/              # Homebrew formula (regenerated by GoReleaser on release)
```

See [`agents.md`](./agents.md) for the operator/agent reference and
[`spec/readme.md`](./spec/readme.md) for the design specification.
