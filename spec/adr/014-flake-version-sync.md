# Keeping `flake.nix` in sync with release tags

* Status: accepted
* Deciders: fw
* Date: 2026-06-15

## Context and Problem Statement

`nebula-pki` is shipped through two installers: Homebrew and a Nix flake.
Both consume the same GoReleaser-built artifacts in spirit, but the
machinery that keeps them aligned with the latest tag differs:

* **Homebrew.** GoReleaser regenerates `Formula/nebula-pki.rb` on every
  tagged release, with the new version string and four per-platform
  SHA256s, and commits the result back to `main` ([milestone
  v0.1](../milestones/v0.1.md), [`.goreleaser.yaml`](../../.goreleaser.yaml)).
  The formula moves automatically; operators always see the current tag.

* **Nix flake.** [`flake.nix`](../../flake.nix) carries a literal
  `version = "0.0.x";` attribute and a `vendorHash`. Today nothing
  updates them on release. Two things go wrong:

  1. The `version` string baked into the flake-built binary's
     `internal/buildinfo.Version` lags the latest tag. Operators running
     `nix run github:anverse/nebula-pki -- --version` see whatever
     version was last hand-edited into `flake.nix`.
  2. When `go.mod` changes the stored `vendorHash` also goes stale, so
     `nix build` against `main` (or any pinned ref) fails until somebody
     edits the file.

This document picks a single mechanism for keeping `flake.nix` in lockstep
with the released tag and spells out what changes elsewhere to support it.

The flake does **not** need a per-release source SHA256: `src = ./.;` builds
from whatever ref Nix evaluates against. That property removes a class of
work the Homebrew side has to do; the only release-coupled values are
`version` and `vendorHash`.

## Decision Drivers

* Single command to cut a release. The operator's full workflow is one
  invocation; the rest is automation.
* `nix run github:anverse/nebula-pki/v0.0.X -- --version` reports
  `0.0.X`, not `0.0.(X-1)`. A pinned-tag consumer must see consistent
  metadata.
* No PATs, no separate bot accounts, no review queue blocking a release.
* The bump logic lives in version control, runs identically locally and
  in CI, and is observable in `git log` rather than in workflow YAML.
* Small surface area in GitHub Actions. The release workflow stays the
  thin layer it is today ([`.github/workflows/release.yml`](../../.github/workflows/release.yml)).

## Decision Outcome

Chosen: **Option D — pre-tag bump driven by a Taskfile `release` target.**

A `task release VERSION=v0.0.X` target on the operator's workstation:

1. Refuses to run if `VERSION` is missing, not in `vX.Y.Z` form, or the
   working tree is dirty.
2. Updates the `version` attribute in `flake.nix` to the bare semver
   (`0.0.X`).
3. Re-pins `vendorHash`: sets it to `lib.fakeHash`, runs `nix build .#default`
   to obtain the real hash from the failure message, writes that back.
   When `go.mod` is unchanged this is a no-op write of the same hash.
4. Runs `nix build .#default` again to confirm the bumped flake builds.
5. Commits the change with a fixed message (`release v0.0.X`),
   matching the project's imperative one-line commit style. The message
   is intentionally generic so future release-prep work (changelog
   stamps, version files, anything else that has to land at the tagged
   commit) can extend the same script without renaming the message.
6. Creates an annotated tag `v0.0.X` on that commit.
7. Pushes the commit and the tag in one `git push --atomic` so the
   tag-push trigger ([`.github/workflows/release.yml`](../../.github/workflows/release.yml))
   never sees a tag without its preparatory commit.

GoReleaser then runs from CI on the tag-push trigger as today, builds the
archives, regenerates `Formula/nebula-pki.rb`, and commits the formula
back to `main` (one extra Homebrew commit on top of the bump commit).

The commit chain on `main` after release is:

```
... → <bump commit, tagged v0.0.X> → <Homebrew formula commit>
```

`flake.nix` at the tagged commit already names version `0.0.X`. A
consumer running `nix run github:anverse/nebula-pki/v0.0.X -- --version`
sees `0.0.X`. A consumer tracking `main` sees the same version with one
extra commit of unrelated Homebrew metadata.

CI on PRs continues to run `nix build .#default` ([`ci.yml`](../../.github/workflows/ci.yml)),
so a stale `vendorHash` in `flake.nix` after a `go.mod` change surfaces
as a red CI run on the PR that introduced the dependency change — not
later, in a release.

### Positive Consequences

* The tag itself points at a tree that builds correctly under both
  GoReleaser and Nix. No off-by-one between installer and binary.
* The release workflow stays a thin GoReleaser invocation; no extra
  permissions, scripts, or PR-bot dance bolted on.
* The bump script is plain shell + `git` + `nix`. Anything it does, an
  operator can do by hand if the script breaks.
* `flake.lock` is left alone unless an explicit `task flake:update` is
  run. Releases do not silently churn nixpkgs.

### Negative Consequences

* `git tag X && git push --tags` alone is no longer sufficient. The
  operator must use `task release VERSION=vX.Y.Z`. The script enforces
  this — there is no path where someone tags from their laptop and
  forgets the bump.
* If the bump script fails halfway (e.g. `nix build` red because of a
  genuine code defect), a stray bump commit may already be on the local
  branch. Recovery is `git reset --hard origin/main`. The script
  documents this and refuses to push if the tag already exists.
* A `vendorHash` rebuild requires `nix` on the operator's workstation.
  This is already a project prerequisite (the dev shell ships from
  `flake.nix`), so it is not a new constraint.

## Considered Options

### A. Direct commit on `main` after the release runs (post-tag bump)

The release workflow runs GoReleaser as today, then runs an extra step
that bumps `flake.nix` and pushes the result to `main`.

* Good, because it keeps the trigger on the operator's side as
  `git tag && git push --tags` — no Taskfile target required.
* Good, because it mirrors how the Homebrew formula commit is delivered
  today — one mechanism for both installers.
* Bad, because the *tag itself* points at a tree where `flake.nix` still
  names the previous version. A user running
  `nix run github:anverse/nebula-pki/v0.0.X -- --version` builds a
  binary that self-reports `0.0.(X-1)`. Only a consumer tracking `main`
  sees the right number, and only after the post-release commit lands.
* Bad, because that off-by-one is invisible to the publisher (their
  fresh checkout of `main` always shows the new version) but visible to
  every Nix consumer who pins to a tag, which is the recommended pinning
  strategy.

Rejected for the version-skew reason. The Homebrew comparison is
misleading: the Homebrew formula is an *install descriptor*, not the
binary itself, so "the formula at the tag is one commit behind" doesn't
produce a wrong version *string at runtime*. A flake is both descriptor
and build, so the same trick produces a wrong version string.

### B. PR-based bump after release

The release workflow opens a PR titled "bump flake to vX.Y.Z" against
`main`. Human merges. (This is the option originally written in the
[v0.1 milestone](../milestones/v0.1.md): *"Automated by a small CI step
that opens a PR against `main` after the release."*)

* Good, because a `nix build` runs in CI on the PR, so a bad
  `vendorHash` is caught before it lands.
* Good, because every flake change is reviewable in `git log`.
* Bad, because it introduces a manual gate in what should be a
  hands-off release pipeline. The decision driver explicitly excludes
  manual steps after `task release`.
* Bad, because the same off-by-one as Option A applies: while the PR
  sits open, the tag-pinned Nix install is wrong.

Rejected. The PR-review value is real but does not pay for the latency
or for the version skew during the review window.

### C. Force-push the tag after the post-release bump

Run the post-release bump exactly as in Option A, then move the tag with
`git tag -f vX.Y.Z && git push --force-with-lease origin vX.Y.Z`.

* Good, because it removes the version-skew problem.
* Bad, because force-pushing a release tag is broadly considered an
  anti-pattern. Anyone who fetched the tag in the window between the
  GoReleaser run and the move now has a different commit than the
  current tag points to.
* Bad, because some artifact stores and signing systems treat a moved
  tag as evidence of tampering.
* Bad, because GoReleaser already produced GitHub release assets, a
  source tarball, and a Homebrew formula commit pinned to the original
  tag commit. Moving the tag desynchronises every one of those.

Rejected.

### D. Pre-tag bump driven by a Taskfile target on the operator's
workstation (chosen)

See [Decision Outcome](#decision-outcome) above.

* Good, because the tag points at a tree that is internally consistent.
* Good, because the release workflow YAML stays unchanged.
* Good, because the bump logic is a normal shell script — testable,
  reviewable, runnable by hand if needed.
* Bad, because cutting a release now requires `task release VERSION=…`,
  not raw `git tag`. Documented in [`development.md`](../../development.md);
  the script is written to fail closed if invoked wrong.

Accepted.

## Implementation notes

These notes are concrete enough to implement directly; they are part of
the decision, not separate work.

* **Script.** `scripts/release.sh`, called by the Taskfile target. Pure
  bash, `set -euo pipefail`. Does the seven steps listed in
  [Decision Outcome](#decision-outcome). Refuses to run on a dirty tree,
  on an existing tag, or with a malformed version.
* **`vendorHash` re-pinning.** The script writes `vendorHash =
  lib.fakeHash;`, runs `nix build .#default 2>&1 | tee` capturing
  output, parses the suggested `got: sha256-…` line, and writes that
  back. This is the same dance described in the inline comment in
  [`flake.nix`](../../flake.nix). The script is the canonical place for
  it; the comment in `flake.nix` is updated to point at the script.
* **Taskfile.** A new `release` target wraps the script. `task release`
  with no `VERSION` exits with a clear usage message. `task
  release:snapshot` (already present) is unchanged.
* **CI.** No change to [`.github/workflows/release.yml`](../../.github/workflows/release.yml).
  The existing tag-push trigger and GoReleaser invocation already do the
  right thing once the tag exists. The PR `nix build` job in
  [`ci.yml`](../../.github/workflows/ci.yml) continues to catch stale
  `vendorHash` between releases.
* **Version string in `flake.nix`.** The script writes the bare semver
  (no `v` prefix), matching the existing format and the value GoReleaser
  injects via `-ldflags`. The Git tag keeps the `v` prefix as required
  for Go modules ([`development.md`](../../development.md)).

## Links

* [Milestone v0.1](../milestones/v0.1.md) — flake/Homebrew shipping
  story; the original "PR after release" sentence is superseded by this
  ADR.
* [`.goreleaser.yaml`](../../.goreleaser.yaml) — Homebrew formula
  generation that this ADR mirrors in spirit but not in mechanism.
* [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
  — unchanged release workflow.
* [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) —
  PR `nix build` that catches stale `vendorHash`.
* [`flake.nix`](../../flake.nix) — `version` and `vendorHash` are the
  two values touched on each release.
* [`development.md`](../../development.md) — release procedure prose.
