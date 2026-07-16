# Taskfile as single entrypoint for CI Go pipeline steps

* Status: accepted
* Deciders: fw
* Date: 2026-07-16

## Context and Problem Statement

The project has two independent representations of "what it means to verify
the codebase":

1. **Taskfile** — `task lint`, `task test`, `task e2e`, and the composite
   `task verify`. These are the targets developers run locally.
2. **`ci.yml` `test` job** — inline shell commands (`go vet ./...`, `gofmt
   -l .` check, `go test ./...`, `go test ./test/e2e/...`) that duplicate
   the same logic.

Any change to verification behaviour — tighter linting, a new test flag, a
changed package path — must be applied in two places. The gap between them
is invisible until a change passes locally but CI applies different rules, or
vice versa.

CI pipelines are difficult to debug by iteration: a push-and-wait cycle is
slow, and the `act` family of local-runner tools introduces its own
divergence. Having the Taskfile as the authoritative definition and having CI
call it means the developer can reproduce any CI step exactly by running the
same `task` target.

## Decision Drivers

* Single source of truth for what "lint", "test", and "e2e" mean.
* Ability to reproduce any CI check locally without knowing the pipeline YAML.
* Minimal overhead in the Action (tooling install should be a one-liner).
* CI portability: if the pipeline host changes, logic stays in-repo.
* No disruption to the goreleaser or nix workflows, which have non-trivial
  action-managed setup.

## Decision Outcome

Chosen: **install Task in CI via `arduino/setup-task` and replace the inline
Go steps with explicit `task` invocations.**

The `test` job in [`ci.yml`](../../.github/workflows/ci.yml) changes to:

```yaml
- uses: arduino/setup-task@v2
- name: lint
  run: task lint
- name: unit tests
  run: task test
- name: e2e tests
  run: task e2e
```

The three calls map exactly to the existing Taskfile targets and are
equivalent to the four inline steps they replace:

| Replaced step | Task target |
|---|---|
| `go vet ./...` | `task lint` (first command) |
| `gofmt -l .` check | `task lint` (second command) |
| `go test ./...` | `task test` |
| `go test ./test/e2e/...` | `task e2e` |

Keeping the three targets as separate steps (rather than calling `task
verify`) preserves per-step failure visibility in the Actions UI and avoids
adding a `task build` step that the current job does not perform. The
composite `task verify` (lint + build + test + e2e) remains available for
local pre-push checks.

### What is deliberately excluded

**goreleaser-action** is left as the driver for the snapshot and release
jobs. The action manages the goreleaser tool version, injects `GITHUB_TOKEN`,
and the `--skip=publish` flag differs between local (`task
goreleaser:snapshot`) and CI. Replacing it with a `task` call would require
splitting tool installation from execution, and the marginal gain is low.
The Taskfile `goreleaser:snapshot` target remains a convenient local alias.

**nix build** in the `nix-build` job is left as a direct `nix build
.#default` invocation after `cachix/install-nix-action`. The action handles
the Nix install and cache configuration; the build line itself is already
thin. The Taskfile has a `nix:build` target for local use; mirroring it in
CI saves one line at the cost of another setup step, which is not worthwhile.

**Nix in CI for Go steps** — using the Nix dev shell to provide Go and Task
in Actions was considered. It would make the tool environment fully
declarative. It was not chosen because:
* `cachix/install-nix-action` + Nix evaluation adds 60–120 s to the job
  even with a warm cache.
* The Nix flake's Go version and the `actions/setup-go` version would need
  to be kept in sync separately; a mismatch between them is harder to
  diagnose than a mismatch in a single `go-version:` field.
* GitHub's free cache storage has a 10 GB rolling limit; the Nix store for
  this project already accounts for a meaningful share of it in the
  `nix-build` job.
* The portability benefit of Nix-in-CI is real but is better captured at
  the Taskfile layer (which is what this ADR does) rather than at the
  environment layer.

### Positive Consequences

* Any change to linting or test flags is made once, in the Taskfile, and
  takes effect in both local runs and CI.
* A developer can run `task lint && task test && task e2e` to reproduce the
  exact CI check before pushing.
* If the project ever migrates away from GitHub Actions, the pipeline logic
  stays in-repo in the Taskfile; the new CI driver is a thin wrapper.

### Negative Consequences

* CI jobs in the `test` job now require `arduino/setup-task` before they
  can call `task`. This is a fast step (single binary download, ~2–3 s) but
  it is a new dependency in the Action.
* The goreleaser and nix jobs remain independent of the Taskfile; the
  single-entrypoint property is partial, not total.

## Considered Options

### A. Call `task verify` instead of three separate targets

`task verify` groups lint + build + test + e2e in one invocation, which
matches the recommended local pre-push workflow.

* Good, because the CI YAML is a single step.
* Bad, because it adds `task build` to a job that currently does not build
  — the goreleaser snapshot job owns builds. This is not harmful but it is
  a silent scope change.
* Bad, because a failure anywhere in `verify` shows as a single failed step;
  separating `lint`, `test`, and `e2e` gives a precise failure signal in
  the Actions UI.

Not chosen. The three-target form is more informative and faithful to the
existing job structure.

### B. Use the Nix dev shell as the CI environment

Install Nix in all jobs and run commands inside `nix develop`:

```yaml
- run: nix develop --command task lint
```

* Good, because the tool environment is identical to the local dev shell.
* Bad, because every job incurs Nix setup overhead even when it only needs Go.
* Bad, because the store cache competes with other caches for GitHub's 10 GB
  limit, and Nix builds add meaningful data to that budget.
* Bad, because `cachix/install-nix-action` would need to appear in all jobs,
  not just `nix-build`.

Rejected. The environment parity argument is compelling but the cost in
complexity and latency is not justified for a pure-Go pipeline.

### C. Keep CI and Taskfile independent

Accept the duplication as a deliberate separation between "what developers
run" and "what CI runs", updated independently when needed.

* Good, because CI steps can be tuned for the actions environment (e.g.
  `::error::` annotations) without touching the Taskfile.
* Bad, because drift is silent and inevitable.
* Bad, because the developer cannot reproduce a CI failure by running a task.

Rejected. The debugging benefit of a shared entrypoint outweighs the
flexibility of independent evolution.

## Links

* [`Taskfile.yml`](../../taskfile.yml) — `lint`, `test`, `e2e`, and `verify` targets.
* [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) — updated workflow.
* [`arduino/setup-task`](https://github.com/arduino/setup-task) — action used to install Task.
* [ADR 014](./014-flake-version-sync.md) — prior decision to drive the release
  from the Taskfile rather than raw `git tag`; this ADR extends the same
  Taskfile-as-entrypoint principle to CI verification.
