# A CA is pinned to its label

* Status: accepted
* Deciders: fw
* Date: 2026-10-04 (extended 2026-10-05 from reference-mode to generate-mode CAs; 2026-10-08 labels renamed only in case)

## Context and Problem Statement

Every `ca` block is identified by its label. The manifest records the CA's fingerprint under that label, and every cert record names its signing CA by label. Certs re-sign when their signing CA *label* changes, not when the CA behind a label changes.

So when the CA behind a label changed, the tool produced a tree in which certs, trust bundles and the manifest no longer matched, with nothing printed, to be found when the files were rolled out:

- **Reference mode.** The content behind `cert_file`/`key_file` changed. The tool recorded the new fingerprint and rewrote the trust bundles, but the certs stayed signed by the old CA.
- **Generate mode, files deleted.** A CA the manifest recorded, whose cert and key were both gone, was silently generated anew under the old label. Existing certs stayed signed by the lost CA.
- **Generate mode, files replaced.** A different CA in the generated files (for example `out/` checked out from the wrong branch) was not noticed: new certs were signed with whatever was on disk while the manifest kept the old fingerprint.
- **Generate mode, encrypted key replaced.** A plaintext key is checked against the CA certificate when the CA is loaded. An encrypted key was only decrypted to sign and never checked, so a key from another CA signed certs that do not verify.

Ways a CA changes under its label:

1. **Deliberate replacement.** The CA expires or its key is lost, and the operator creates a new one at the same path, or deletes the files to get a fresh one, and reruns.
2. **Accidental replacement.** The files come from a git checkout on the wrong branch, from the wrong environment through a mistyped path or flag, or were deleted by mistake.
3. **Re-issued CA certificate.** The same key re-signs a CA certificate with a new validity, or converts it between certificate versions. The fingerprint changes, and Nebula matches a cert's issuer by fingerprint, so this is a different CA as far as existing certs are concerned.

Moving the same CA to another path, restoring it from a backup or re-encoding the PEM keeps the fingerprint and is not a change.

## Decision

The tool optimises for transparency: a CA is pinned to its label by the fingerprint the manifest records. When the CA behind a label is not that CA, the run fails before anything is written, and `--dry-run` fails the same way.

| CA state | Result |
|---|---|
| Reference mode, certificate fingerprint differs from the record | `ca "x": referenced CA changed: cert_file ext/ca.crt has fingerprint <new>, but the manifest records <old> for this label; restore the recorded CA, or declare the new CA under a new label (move default = true and update ca_refs) to switch to it` |
| Generate mode, recorded, both files missing | `ca "x": CA files missing: neither out/ca/x.crt nor out/ca/x.key exists, but the manifest records CA <fp> for this label; restore them, or declare the new CA under a new label (…)` |
| Generate mode, recorded, certificate fingerprint differs | `ca "x": CA certificate changed: out/ca/x.crt has fingerprint <new>, but the manifest records <old> for this label; restore the recorded CA, or declare the new CA under a new label (…)` |
| Declared label not recorded, but a removed recorded label equals it ignoring case (either mode) | `ca "X": label differs only in case from ca "x", which the manifest records; a CA is pinned to its label, so restore the label "x", or declare the new CA under a new label (…)` |
| Generate mode, encrypted key does not belong to the certificate | `cert "y": ca "x": CA key does not match certificate "x" (public keys differ)`, when the key is decrypted to sign |

- **Switching CAs takes a new label.** A new label is a new signing CA, so every cert it signs is re-signed and every bundle that lists it is rewritten, which is the rotation flow of [ADR-016](./016-ca-rotation-and-trust-bundles.md) and [ADR-026](./026-trust-bundle-block.md). The old label's record is dropped; its files are reported as no longer managed only when they still exist.
- **Starting from scratch** stays possible: deleting all of `out/`, manifest included, leaves nothing to compare against.
- **Moving is fine.** A changed reference `cert_file`/`key_file` path with the same fingerprint updates the recorded paths and re-signs nothing.
- **No record, no check.** On a first run, after the manifest was deleted, or for a new label there is nothing to compare against, and a generate-mode CA is generated as before. The missing-files rule applies whatever mode the record has, so switching a label from reference to generate mode is an error too.
- **A label renamed only in case is refused (added 2026-10-08).** Labels are unique ignoring case within a config (ADR-026 "Detailed rules"), and the default CA files are named after the label. Renaming `ca "mesh"` to `ca "Mesh"` used to depend on the filesystem: on a case-insensitive one (macOS) `out/ca/Mesh.crt` found the old CA's files and the run failed with a misleading "untracked CA" error, on a case-sensitive one (Linux) a new CA was generated. The planner now refuses it on every platform, for both modes, before anything is written: restore the recorded label, or take a label that differs by more than case. A reference-mode CA would technically survive the rename, but one rule for every CA is easier to state and to check.
- **The planner decides.** The fingerprint checks run while the plan is built, through a read-only fingerprint probe supplied by the caller, so `--dry-run` and the run agree. With them in place a trust bundle never sees a swapped member, so the bundle planner compares recorded fingerprints only.
- **Encrypted keys are checked when decrypted.** The key is decrypted only when a cert needs signing, and is checked against the CA certificate before it signs anything. A run in which every cert is up to date never decrypts the key, so it cannot notice a swapped key; nothing is signed, and the next run that signs fails.
- **`nebula-pki check` does not run the fingerprint checks.** `check` performs no I/O against `out/`, where the manifest lives.

Case 1 costs one extra step (edit the label, rerun), and the error message names it. Case 2 is caught before the wrong CA reaches certs or bundles, which is the point of the rule.

## Consequences

### Positive

- Certs, trust bundles and the manifest cannot silently drift apart through a changed, replaced or deleted CA file.
- The rule matches how the rest of the config works: a label is an identity, and a change of identity is a config edit, not a side effect.
- The cert idempotency rule in [ADR-002](./002-state-and-artifact-layout.md) compares the signing CA by label; with CAs pinned to their labels that is equivalent to comparing the recorded `ca_fingerprint`.

### Negative

- A deliberate in-place replacement, or a lost CA that should be replaced, needs a label change. Accepted: it is a one-line edit, and it makes the rotation visible in the config and the manifest.

## Considered alternatives

### A. Accept the new CA silently (previous behaviour)

Record the new fingerprint (reference mode) or generate a new CA (generate mode, files deleted). Rejected: it leaves certs signed by a CA the bundles no longer contain, without notice.

### B. Re-sign every cert of a changed CA automatically

Treat a changed signing-CA fingerprint as one more re-sign trigger. Rejected for now: it turns an accidental swap (case 2) into a full re-issue against the wrong CA, which is worse than an error.

### C. Warn and continue

Rejected: a warning in a routine run is easy to miss, and the tree is already inconsistent by the time it is read.

### D. Opt-in flag that accepts a changed CA (future idea, not built)

A flag such as `--accept-changed-ca` would record the new fingerprint, or generate a replacement for a lost generate-mode CA, and re-sign the affected certs (alternative B, but only on request). It would make case 1 a single command without weakening the default. Recorded as a future idea; the label change covers the need today.

## Links

- [ADR-002](./002-state-and-artifact-layout.md): manifest as the source of truth, cert idempotency.
- [ADR-013](./013-atomic-artifact-writes.md): the tool never overwrites an untracked CA.
- [ADR-016](./016-ca-rotation-and-trust-bundles.md): rotation via a new CA block.
- [ADR-026](./026-trust-bundle-block.md): trust bundles, the planner as the only place that decides writes.
