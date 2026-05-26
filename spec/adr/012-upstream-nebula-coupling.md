# Upstream Nebula coupling and version compatibility

* Status: accepted
* Deciders: fw
* Date: 2026-05-26

## Context and Problem Statement

`nebula-pki` presents itself as a wrapper around `nebula-cert`. That framing is correct at the conceptual level — HCL fields mirror `nebula-cert` flags 1:1 and the produced artifacts are byte-identical to what `nebula-cert` would emit — but it leaves two practical questions unanswered:

1. **Runtime dependency.** Does an operator need `nebula-cert` (or any other piece of the upstream Nebula distribution) installed alongside `nebula-pki`?
2. **Version compatibility.** Which `slackhq/nebula` version do `nebula-pki` artifacts correspond to, and how does that surface to operators who also use `nebula-cert` directly to inspect or verify certificates?

[ADR-001](./001-tooling-approach.md) decided the wrapper is implemented as a custom Go CLI linking the `slackhq/nebula/cert` library. It did not spell out the operator-visible consequences. This ADR closes that gap.

## Decision Drivers

* Self-contained distribution — a single static binary, the same property promised for the sops backend ([ADR-003](./003-encryption-strategy.md)).
* No drift between what `nebula-pki` produces and what upstream `nebula-cert` would accept.
* Predictable upgrade story for operators who pin tool versions.
* Minimum maintenance burden — we do not want to track or shim multiple upstream versions in parallel.

## Decision Outcome

1. **Compile-time coupling, no runtime dependency.** `nebula-pki` links `github.com/slackhq/nebula/cert` (and the small surface of `github.com/slackhq/nebula` it requires) directly. The `nebula-cert` binary is never exec'd. Operators do not install Nebula to run `nebula-pki`.
2. **Single pinned upstream per release.** Every `nebula-pki` release pins exactly one `slackhq/nebula` version in `go.mod`. There is no compatibility matrix; the pinned version *is* the supported version for that release.
3. **Version is observable.** The pinned upstream version is:
    * recorded in release notes,
    * printed by `nebula-pki --version`,
    * embedded in the manifest under `generator.nebula_library_version` (see [ADR-002](./002-state-and-artifact-layout.md) for the manifest schema; this field is additive and does not require a `schema_version` bump).
4. **Cert format versions track upstream.** The HCL `version` field on `ca` and `host` (cert format 1 or 2) maps directly to upstream's `--version` flag. We support whichever format versions the pinned upstream supports — no parallel format, no shimming.
5. **Artifact compatibility contract.** Certificates produced by `nebula-pki` at upstream pin `vX` are byte-identical (modulo expected non-deterministic fields like signing nonces) to what `nebula-cert sign` from upstream `vX` would produce. Operators may use any `nebula-cert` build that understands the relevant cert format to inspect or verify artifacts.
6. **Upgrade story.** Upgrading the pinned upstream version is a `nebula-pki` release event. If an upstream change alters HCL-visible behaviour (flag rename, semantic shift, new cert format), it is called out in release notes. We do not introduce HCL changes that require a newer upstream than the one currently pinned.
7. **Non-goals.** We do not shim, fork, or extend upstream cert behaviour. If upstream removes or changes a field's semantics, the mirrored HCL field changes in lockstep.

### Positive Consequences

* Operators install one binary. No `nebula-cert` prerequisite, no PATH coordination.
* No version skew between what `nebula-pki` and a co-located `nebula-cert` would produce — they can co-exist if the operator chooses to install both, but it is never required.
* The manifest carries enough information to reproduce a build (`generator.version` + `generator.nebula_library_version`).
* No combinatorial test matrix.

### Negative Consequences

* A new upstream feature (e.g. a new cert format) reaches operators only after a `nebula-pki` release bumps the pin. Operators wanting bleeding-edge upstream behaviour need to build from source.
* Security fixes in `slackhq/nebula/cert` require a `nebula-pki` re-release; there is no way for an operator to swap in a newer upstream library at runtime.

## Considered Options

### A. Exec `nebula-cert` as an external binary

* Good, because operators get whatever upstream version they choose to install.
* Bad, because it adds a runtime dependency and a PATH discovery problem.
* Bad, because parsing the `nebula-cert` CLI output is brittle — there is no stable machine-readable interface.
* Bad, because we lose direct access to library-level primitives (e.g. for fingerprinting, verification, future revocation work — see [ADR-004](./004-revocation-strategy.md)).

Rejected.

### B. Link the library, support a compatibility range

* Good, because operators on older Nebula deployments could pin an older `nebula-pki`.
* Bad, because the upstream library has no stable Go API contract for downstream wrappers; supporting a range means shims and conditional code.
* Bad, because the maintenance burden contradicts ADR-001's "minimum maintenance" driver.

Rejected.

### C. Link the library, pin one version per release (chosen)

* Good, because it is the simplest model that delivers a self-contained binary.
* Good, because correctness is provable: one pin, one behaviour.
* Bad, because operators cannot independently track upstream releases.

Accepted.

## Links

* [ADR-001](./001-tooling-approach.md) — Tooling approach (custom Go CLI).
* [ADR-002](./002-state-and-artifact-layout.md) — Manifest schema (where `generator.nebula_library_version` lives).
* [ADR-003](./003-encryption-strategy.md) — Self-contained sops backend (same self-contained property, different dependency).
* [ADR-007](./007-schema-evolution.md) — Schema evolution (manifest field additions are additive).
* Upstream: <https://github.com/slackhq/nebula>.
* Upstream cert package: <https://pkg.go.dev/github.com/slackhq/nebula/cert>.
