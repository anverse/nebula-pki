# nebula tooling — specification

This directory specifies a small CLI that wraps `nebula-cert` with a declarative HCL configuration.

It is the source of truth for the project. The code can be discarded and recreated from these files alone.

## Purpose

Replace ad-hoc shell scripts for Nebula CA and certificate provisioning with a single declarative workflow: edit one HCL file, run one command, get a consistent set of artifacts on disk that downstream tooling can consume across many providers and projects.

## Scope (v1)

The tool:

- Parses a declarative HCL spec that maps closely to `nebula-cert ca` and `nebula-cert sign` flags.
- Generates one or more Nebula CAs, or uses existing CAs referenced by file path. Multiple labelled CAs in one file enable CA rotation; see [ADR-015](./adr/015-multiple-cas-per-config.md).
- Signs one certificate per `cert` block using the upstream `slackhq/nebula/cert` Go library — same primitives as `nebula-cert`. Each cert selects its signing CA via `cert.ca`, or the CA marked `default = true`.
- Signs device-supplied public keys (`cert.in_pub`) for the "private key never leaves the device" pattern — mobile, HSM, separation of duties; see [ADR-018](./adr/018-in-pub-air-gapped-signing.md).
- Emits a concatenated-PEM **trust bundle** for downstream `pki.ca` when a `trust_bundle` block declares one, and supports declarative CA rotation across an overlap window; see [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md). Bundle membership is explicit via the block's `ca_refs` (with `link_crt` fan-out of the bundle itself); without the block no bundle is written. See [ADR-026](./adr/026-trust-bundle-block.md).
- Re-signs certificates before expiry when a `renew_before` threshold is set, and after each run prints the earliest upcoming renewal/expiry deadline so the operator knows when to run again; see [ADR-017](./adr/017-cert-renewal-threshold.md).
- Writes artifacts to configurable paths. Each cert and its key land in a directory configured via `cert.output_dir` (defaults to `<storage.out_dir>/certs`); `out_crt` / `out_key` override the path component within that directory.
- Optionally encrypts private key material at rest via pluggable **storage encryption backends** (built-in: `none`, `sops`; extensible via `external` command).
- Maintains a git-committable **manifest** tracking certificate fingerprints, validity windows, signing-CA relationships, and the full artifact layout. The manifest contains **no secret material**.
- Is idempotent: re-running with an unchanged spec produces no churn; changed spec produces minimal diffs.

## Non-goals

- **Distribution to certs.** Downstream Terraform projects pick up the on-disk files via `file()` / `local_file`. The tool never SSHes anywhere. This includes distributing the trust bundle and reloading daemons during a CA rotation — the tool emits the artifacts; the operator ships them. See [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md).
- **`config.yaml` rendering.** Each consuming project templates its own nebula configuration from the certificates and manifest produced here.
- **Lighthouse / runtime concepts.** Lighthouse, blocklist, firewall rules, listening ports — all of these are runtime config concerns and have no `nebula-cert` equivalent. They live in the downstream `config.yaml`, not here.
- **Revocation.** No blocklist management. See ADR-004. (Retiring a CA removes trust in its signatures via the bundle; per-cert blocklisting stays downstream.)
- **Drift detection against remote certs.** Manifest reflects what the tool last wrote, nothing more.
- **Multi-operator concurrency / locking.** Single-operator assumption.
- **Background/daemon operation.** `renew_before` acts only when the tool is invoked; cadence comes from the operator's scheduler, not a long-running process. See [ADR-017](./adr/017-cert-renewal-threshold.md).
- **A `keygen` subcommand.** Device keypairs are generated on the device (`nebula-cert keygen` or the mobile app), never on the CA workstation; see [ADR-018](./adr/018-in-pub-air-gapped-signing.md).
- **General-purpose sops wrapper.** Encryption is scoped strictly to this tool's artifacts.
- **A Terraform provider.** Evaluated and rejected; see ADR-001.

## Deferred capabilities (named so YAGNI is deliberate)

- Per-node `config.yaml` rendering.
- Background auto-renewal as a service (the `renew_before` threshold exists, but running on a schedule is the operator's job; see [ADR-017](./adr/017-cert-renewal-threshold.md)).
- `--force` re-sign of everything regardless of the idempotency verdict.
- PKCS#11 / HSM-backed CAs.
- Full v1→v2 / IPv6 certificate migration automation (the multi-CA + bundle machinery is the substrate, but the migration itself is not built; see [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md)).
- Go-plugin-based extension system (current model is built-in backends + external command; see ADR-006).
- Schema versioning in HCL (deferred until a real breaking change is needed; see ADR-007).

## Document map

- [`hcl-schema.md`](./hcl-schema.md) — user-facing HCL reference, annotated examples.
- [`hcl-schema.formal.json`](./hcl-schema.formal.json) — JSON Schema describing the HCL contract.
- [`adr/001-tooling-approach.md`](./adr/001-tooling-approach.md) — why a custom Go CLI.
- [`adr/002-state-and-artifact-layout.md`](./adr/002-state-and-artifact-layout.md) — directory layout and manifest format.
- [`adr/003-encryption-strategy.md`](./adr/003-encryption-strategy.md) — sops as a thin pass-through; honours `.sops.yaml`.
- [`adr/004-revocation-strategy.md`](./adr/004-revocation-strategy.md) — revocation out of scope; rationale.
- [`adr/005-hcl-schema-decision.md`](./adr/005-hcl-schema-decision.md) — schema design rationale.
- [`adr/006-storage-backend-extensibility.md`](./adr/006-storage-backend-extensibility.md) — pluggable encryption backends.
- [`adr/007-schema-evolution.md`](./adr/007-schema-evolution.md) — breaking-change policy and the deferred `nebula_pki { schema = N }` block.
- [`adr/008-cli-surface.md`](./adr/008-cli-surface.md) — default reconcile action with `--dry-run` and `check`; why we don't mirror Terraform's verbs.
- [`adr/009-cert-label-vs-cert-name.md`](./adr/009-cert-label-vs-cert-name.md) — why each `cert` block has both a label (manifest key) and an optional `name` field (cert CN).
- [`adr/010-single-ca-per-config.md`](./adr/010-single-ca-per-config.md) — one CA per HCL file (superseded by ADR-015).
- [`adr/011-output-blocks-are-directories.md`](./adr/011-output-blocks-are-directories.md) — fan-out design context (superseded by ADR-020).
- [`adr/012-upstream-nebula-coupling.md`](./adr/012-upstream-nebula-coupling.md) — compile-time coupling to `slackhq/nebula`, no runtime dependency, version-compatibility policy.
- [`adr/013-atomic-artifact-writes.md`](./adr/013-atomic-artifact-writes.md) — crash-safe per-file writes via temp+rename; what it guarantees for operators and what it deliberately does not.
- [`adr/014-flake-version-sync.md`](./adr/014-flake-version-sync.md) — pre-tag flake bump driven by `task release`; why the tag must already carry the new `version`/`vendorHash`.
- [`adr/015-multiple-cas-per-config.md`](./adr/015-multiple-cas-per-config.md) — labelled `ca` blocks, `cert.ca`, `ca.default`; additive multi-CA superseding ADR-010.
- [`adr/016-ca-rotation-and-trust-bundles.md`](./adr/016-ca-rotation-and-trust-bundles.md) — declarative CA rotation, the emitted trust bundle, signing-CA vs. trusted-set.
- [`adr/017-cert-renewal-threshold.md`](./adr/017-cert-renewal-threshold.md) — `renew_before`; time-based re-signing before expiry.
- [`adr/018-in-pub-air-gapped-signing.md`](./adr/018-in-pub-air-gapped-signing.md) — signing a device-supplied public key, config-only, no `keygen` subcommand.
- [`adr/019-manifest-compactness.md`](./adr/019-manifest-compactness.md) — omit optional fields when empty; policy for which manifest fields carry `omitempty`.
- [`adr/020-output-dir-per-cert.md`](./adr/020-output-dir-per-cert.md) — single `output_dir` per cert replacing the `output_dirs` list; composable `out_crt` / `out_key` path components. Supersedes ADR-011.
- [`adr/021-ca-cert-links.md`](./adr/021-ca-cert-links.md) — `link_crt` symlink fan-out of CA certificates into cert output directories.
- [`adr/022-taskfile-as-ci-entrypoint.md`](./adr/022-taskfile-as-ci-entrypoint.md) — Taskfile as the single entrypoint for CI and local automation.
- [`adr/023-external-backend-protocol.md`](./adr/023-external-backend-protocol.md) — `encryption "external"` command protocol.
- [`adr/024-rename-host-to-cert.md`](./adr/024-rename-host-to-cert.md) — rename the `host` block to `cert` (pre-1.0 hard switch, shipped first); carries the two-dialects naming rationale.
- [`adr/025-ca-references.md`](./adr/025-ca-references.md) — terraform-style `ca.<label>` references for `cert.ca`: one spelling, no evaluation, source-ranged errors; the reserved-root convention.
- [`adr/026-trust-bundle-block.md`](./adr/026-trust-bundle-block.md) — explicit `trust_bundle` block: declared trust membership via `ca_refs`, bundle `link_crt`, removal of `archived`; carries the `trust_bundle`/`ca_refs` naming rationale. Amends ADR-016.

## Operating model

1. Operator edits `nebula.hcl`.
2. Operator runs the CLI (`nebula-pki` to reconcile; `nebula-pki --dry-run` to preview; `nebula-pki check` to validate config).
3. CLI writes (or reuses) the CA, signs certs to each cert's configured `output_dir` (or the default `<storage.out_dir>/certs`), updates `nebula-pki.json` (renameable via `storage.manifest_file`).
4. Manifest and (encrypted) artifacts are committed to git.
5. Downstream projects (Terraform, Ansible, custom scripts) read the artifacts directly from the per-provider output directories.

## Trust model

- The operator's workstation is the trust boundary. The CLI does not communicate over the network.
- Private key material is either left plaintext on disk (default) or encrypted via a storage backend the operator opts into.
- The age private key (when using the `sops` backend) is the highest-value secret in the system and lives outside the tool's responsibility.
- The CA private key, when in reference mode, is the operator's responsibility — the tool reads it but does not move, copy, or re-encrypt it.
