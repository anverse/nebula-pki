# CLI surface: default reconcile action, not Terraform-style verbs

## Status

accepted

## Context

The tool needs a CLI surface. Two obvious shapes were on the table:

1. **Terraform-style verbs**: `nebula-pki plan`, `nebula-pki apply`, `nebula-pki show`, etc. Familiar to anyone who uses Terraform daily, which is the same audience this tool targets.
2. **Flat / default-action with flags**: invoking the tool reconciles by default; previewing is `--dry-run`; ancillary read-only operations are subcommands only when they take different inputs from the main action.

The deciding question: does the Terraform verb model carry its weight here?

Terraform's `plan` / `apply` split is valuable because Terraform:

- Mutates remote infrastructure with real, sometimes destructive side effects.
- Has a distinct, expensive **refresh** phase that's worth running independently of the change phase.
- Has a meaningful **destroy** verb.
- Operates at a scope where review-before-execute is a workflow norm, not paranoia.

`nebula-pki` has none of these properties:

- It only touches local files in `out/`.
- "Refresh" is reading the manifest — milliseconds.
- "Destroy" is `rm -rf out/`; modelling it as a subcommand would be ceremony.
- The diff between config and on-disk artifacts is cheap to compute and small to display.

The Terraform mental model would impose two-step workflows for a tool whose primary action is so cheap and so safe that a single invocation is the right default.

## Decision

Adopt a **default-action CLI** with `--dry-run` for preview and a small set of read-only subcommands for operations that take genuinely different inputs from the main reconcile.

### v1 surface

```
nebula-pki                # reconcile out/ with nebula.hcl  (default)
nebula-pki --dry-run      # preview only; no writes
nebula-pki check          # parse + validate nebula.hcl; no I/O against out/. In reference mode, reads ca.cert_file / ca.key_file to verify they exist and parse.
nebula-pki -c <path>      # use a different config (default: ./nebula.hcl)
```

Exit codes:

- `0` — success, or clean dry-run.
- `1` — validation or runtime error.
- `2` — usage error (bad flags, missing config).

### Why `check` is a subcommand and `--dry-run` is a flag

`--dry-run` is the standard Unix idiom for "do everything except writes" (`rsync`, `apt`, `kubectl`, `terraform plan -refresh=false` once you've squinted at it). It naturally composes with the default action and any future flags. It belongs on the main verb.

`check` is fundamentally different: it doesn't read `out/`. It only validates the config and, in CA reference mode, reads the referenced CA files to confirm they exist and parse. Squeezing this into the root invocation would mean either a confusing flag combo (`--no-state-access --validate-only`) or overloading `--dry-run` with two meanings. A small dedicated subcommand is clearer.

### Deferred

- `nebula-pki show` — pretty-print the manifest (`out/nebula-pki.json` by default). Useful but not essential; operators can `jq` the manifest. Will be added when the first concrete pain point arrives.
- A `--watch` mode, an `--explain` flag for diff output, any "explain why this cert is being re-issued" tooling — all deferred.

### Explicitly rejected

- `nebula-pki apply` as the main verb. Adds typing to every invocation for no semantic benefit.
- `nebula-pki plan`. `--dry-run` covers the use case with one less command to memorise.
- A REPL or interactive mode.
- An HTTP/RPC server.

## Consequences

- The CLI stays trivially small and discoverable: running `nebula-pki` with no args does the obvious thing.
- Users coming from Terraform need a one-line note that the tool deliberately doesn't mirror TF's verbs. The `readme.md` covers this.
- Adding subcommands later (e.g. `show`, `revoke`, `rotate`) is straightforward — none of the v1 commands occupy contested namespace.
- Scripts and CI can rely on `nebula-pki --dry-run` returning non-zero only on validation/runtime errors, never on "would have made changes". This is consistent with the Unix `--dry-run` convention but worth stating explicitly because Terraform's `plan` returns a non-zero exit code (`-detailed-exitcode=2`) to signal pending changes — `nebula-pki` does **not** do this.
- The flat surface narrows the design space for future features: anything that doesn't fit "reconcile" or a clearly-distinct read-only operation will need its own ADR to justify a new subcommand.

## Links

- [ADR-001](./001-tooling-approach.md) — why a custom Go CLI in the first place.
- [Terraform CLI design](https://developer.hashicorp.com/terraform/cli) — for context on what's being declined.
