# Atomic artifact writes (crash-safe `fsutil`)

* Status: accepted
* Deciders: fw
* Date: 2026-06-14

## Context

A single `nebula-pki` run writes several files: the CA certificate, the CA
private key, host certificates and keys, and the manifest. Two distinct
failure modes threaten that work:

1. **A torn write of one file.** If the process is interrupted *while writing
   a single file* — Ctrl-C, an OOM kill, a full disk, a laptop losing power —
   the standard `os.WriteFile` leaves a **partially written file** on disk. It
   opens the target, truncates it to zero, and streams bytes in place. A crash
   half-way through leaves a truncated, corrupt file *at the real path*.

   For this tool that is not a theoretical concern:

   * A truncated `ca.key` is an **unrecoverable** CA private key. There is no
     "run it again to fix it" — the key material is gone.
   * A truncated `nebula-pki.json` is invalid JSON. The manifest is the tool's
     source of truth across runs ([ADR-002](./002-state-and-artifact-layout.md));
     a corrupt manifest wedges every subsequent run.
   * A downstream reader (Terraform `file()`, Ansible, `git add`, an editor)
     that happens to read `app.crt` *while we are rewriting it* would observe a
     half-written file.

2. **A partial multi-file run.** If the process dies *between* files — say
   after `ca.crt` and `ca.key` but before the manifest — every individual file
   on disk is complete, but the set is incomplete: artifacts exist that the
   manifest does not record.

These are different problems and they have different solutions. Conflating them
leads to either under-engineering (ignoring torn writes) or over-engineering
(reaching for a write-ahead log / two-phase commit this tool does not need).

Upstream `nebula-cert` itself writes with a plain `os.WriteFile(..., 0600)`
(`cmd/nebula-cert/ca.go`). That is acceptable for a one-shot, interactive
command. `nebula-pki` is a **reconciler** that persists state across runs and is
expected to run unattended in CI, so it holds itself to a higher durability bar.

## Decision

Centralise all artifact writes in a small `internal/fsutil` package whose
`WriteFile` is **atomic per file**:

1. Create the parent directory (`0755`) if missing.
2. Write the bytes to a temporary file **in the same directory** as the target,
   created with the target's final mode (e.g. `0600` for keys, so the bytes are
   never momentarily world-readable).
3. `fsync` the temp file.
4. `os.Rename` the temp file over the target.

`rename(2)` is atomic within a single filesystem on POSIX, so any observer — a
crash-recovery run, a concurrent reader — sees the target as *either* its old
contents *or* the complete new contents, never an intermediate state. The
same-directory requirement guarantees the rename stays within one filesystem.
On error the temp file is removed and the original target is left untouched.

`fsutil` deliberately stays tiny: `WriteFile` (atomic) and `Exists`. It owns the
file-mode policy from [ADR-002](./002-state-and-artifact-layout.md) (`0600`
keys/certs, `0644` manifest, `0755` dirs) so those invariants live in exactly
one place and cannot drift across callers. Path resolution is *not* I/O and
lives in `internal/config`, not here.

This decision covers problem (1) — torn single files. Problem (2) — partial
multi-file runs — is **not** solved with a cross-file transaction. Instead:

* The **manifest is written last**, after all artifacts. A run that dies early
  leaves the previous manifest intact (`partial runs leave the previous
  manifest intact`, ADR-002).
* Reconcile is **idempotent**: re-running detects what is already present and
  finishes the remaining work.
* The tool **refuses to overwrite an untracked CA** (cert/key present on disk
  but absent from the manifest), so a partial run can never be silently
  clobbered or mistaken for a clean slate.

A no-op run (nothing changed) writes **nothing at all** — not even the manifest
— so re-running an up-to-date tree produces a byte-identical result and zero VCS
churn.

We do not adopt a third-party atomic-write dependency (e.g. `renameio`): the
primitive is ~30 lines, and [the milestone](../milestones/v0.1.md) keeps the
dependency set to stdlib plus the few libraries already justified.

## Consequences

What this buys `nebula-pki` users, in plain terms:

* **Crash-safe.** Ctrl-C, an OOM kill, a full disk, or a power loss mid-run
  never leaves a corrupt certificate, private key, or manifest. The worst case
  is "some artifacts not written yet" — fixed by running the tool again — never
  "an artifact written but mangled."
* **Safe to read while it runs.** A Terraform plan, a `git commit`, or an editor
  reading `out/` during a run always sees a complete file: either the previous
  version or the new one, never a half-written one.
* **Re-runnable, never hand-fixed.** Recovery from an interrupted run is simply
  running `nebula-pki` again. There is no torn file to delete by hand and no
  "remove the stale lock / temp file" step.
* **No spurious diffs.** Because an up-to-date run writes nothing, committing
  `out/` to git shows a diff only when something genuinely changed.

Costs and limits, stated honestly:

* `WriteFile` is **not** a transaction across files. A crash can still leave a
  partial *set* of artifacts on disk (each individually valid); the manifest-
  last ordering plus idempotent reconcile — not `fsutil` — is what makes that
  state recoverable.
* Atomic rename requires the temp file to share a filesystem with the target,
  which is why the temp file is created in the target's directory rather than
  `$TMPDIR`.
* A brief extra temp file exists during the write. On a hard crash *between*
  `fsync` and `rename` a stray `*.tmp` may remain; it is harmless and
  overwritten on the next run.

## Links

* [ADR-002](./002-state-and-artifact-layout.md) — artifact layout, file modes,
  manifest as source of truth, idempotency rule.
* [Milestone v0.1](../milestones/v0.1.md) — `fsutil` in the package layout;
  stdlib-first dependency policy.
