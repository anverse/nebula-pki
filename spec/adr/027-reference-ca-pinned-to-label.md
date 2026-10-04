# A reference-mode CA is pinned to its label

* Status: accepted
* Deciders: fw
* Date: 2026-10-04

## Context and Problem Statement

A reference-mode `ca` block points at files the operator owns (`cert_file`, `key_file`). The manifest records the CA's fingerprint under the block label, and every cert record names its signing CA by that label.

The content behind those paths can change while the label stays the same. Until now the tool accepted that silently: it recorded the new fingerprint and rewrote the trust bundles, but certs only re-sign when their signing CA *label* changes, so they stayed signed by the old CA. The result was a tree in which certs and trust bundles no longer matched, with nothing printed, to be found when the files were rolled out.

Ways this happens:

1. **Deliberate replacement.** The referenced CA expires, the operator creates a new one at the same path and reruns.
2. **Accidental replacement.** The referenced files come from a git checkout on the wrong branch, or from the wrong environment through a mistyped path or flag.
3. **Re-issued CA certificate.** The same key re-signs a CA certificate with a new validity, or converts it between certificate versions. The fingerprint changes, and Nebula matches a cert's issuer by fingerprint, so this is a different CA as far as existing certs are concerned.

Moving the same CA to another path, restoring it from a backup or re-encoding the PEM keeps the fingerprint and is not a change.

## Decision

The tool optimises for transparency. When a reference-mode CA's certificate fingerprint differs from the fingerprint the manifest records under its label, the run fails before anything is written, and `--dry-run` fails the same way:

```
error: ca "x": referenced CA changed: cert_file ext/ca.crt has fingerprint <new>, but the manifest
records <old> for this label; restore the recorded CA, or declare the new CA under a new label
(move default = true and update ca_refs) to switch to it
```

- **Switching CAs takes a new label.** A new label is a new signing CA, so every cert it signs is re-signed and every bundle that lists it is rewritten, which is the rotation flow of [ADR-016](./016-ca-rotation-and-trust-bundles.md) and [ADR-026](./026-trust-bundle-block.md).
- **Moving is fine.** A changed `cert_file`/`key_file` path with the same fingerprint updates the recorded paths and re-signs nothing.
- **No record, no check.** On a first run, after the manifest was deleted, or for a new label there is nothing to compare against.
- **The planner decides.** The check runs while the plan is built, through a read-only fingerprint probe supplied by the caller, so `--dry-run` and the run agree. With the check in place a trust bundle never sees a swapped reference member, so the bundle planner compares recorded fingerprints only.
- **`nebula-pki check` does not run it.** `check` performs no I/O against `out/`, where the manifest lives.

Case 1 costs one extra step (edit the label, rerun), and the error message names it. Case 2 is caught before the wrong CA reaches certs or bundles, which is the point of the rule.

## Consequences

### Positive

- Certs, trust bundles and the manifest cannot silently drift apart through a changed referenced file.
- The rule matches how the rest of the config works: a label is an identity, and a change of identity is a config edit, not a side effect.

### Negative

- A deliberate in-place replacement needs a label change. Accepted: it is a one-line edit, and it makes the rotation visible in the config and the manifest.

## Considered alternatives

### A. Accept the new CA silently (previous behaviour)

Rejected: it leaves certs signed by a CA the bundles no longer contain, without notice.

### B. Re-sign every cert of a changed reference CA automatically

Treat a changed signing-CA fingerprint as one more re-sign trigger. Rejected for now: it turns an accidental swap (case 2) into a full re-issue against the wrong CA, which is worse than an error.

### C. Warn and continue

Rejected: a warning in a routine run is easy to miss, and the tree is already inconsistent by the time it is read.

### D. Opt-in flag that accepts changed reference CAs (future idea, not built)

A flag such as `--accept-changed-ca` would record the new fingerprint and re-sign the affected certs (alternative B, but only on request). It would make case 1 a single command without weakening the default. Recorded as a future idea; the label change covers the need today.

## Links

- [ADR-016](./016-ca-rotation-and-trust-bundles.md): rotation via a new CA block.
- [ADR-026](./026-trust-bundle-block.md): trust bundles, the planner as the only place that decides writes.
