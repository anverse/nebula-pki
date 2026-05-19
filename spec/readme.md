# nebula tooling — specification

This directory specifies a small CLI that wraps `nebula-cert` with a declarative HCL configuration.

It is the source of truth for the project. The code can be discarded and recreated from these files alone.

## Purpose

Replace ad-hoc shell scripts for Nebula CA and host certificate provisioning with a single declarative workflow: edit one HCL file, run one command, get a consistent set of artifacts on disk that downstream tooling can consume across many providers and projects.

## Scope (v1)

The tool:

- Parses a declarative HCL spec that maps closely to `nebula-cert ca` and `nebula-cert sign` flags.
- Either generates a Nebula CA or uses an existing CA referenced by file path.
- Signs per-host certificates using the upstream `slackhq/nebula/cert` Go library — same primitives as `nebula-cert`.
- Writes artifacts to configurable paths. Hosts fan certificates out to multiple destination directories via `host.output_dirs`, one entry per downstream provider/project/environment.
- Optionally encrypts private key material at rest via pluggable **storage encryption backends** (built-in: `none`, `sops`; extensible via `external` command).
- Maintains a git-committable **manifest** tracking certificate fingerprints, validity windows, and the full artifact layout. The manifest contains **no secret material**.
- Is idempotent: re-running with an unchanged spec produces no churn; changed spec produces minimal diffs.

## Non-goals

- **Distribution to hosts.** Downstream Terraform projects pick up the on-disk files via `file()` / `local_file`. The tool never SSHes anywhere.
- **`config.yaml` rendering.** Each consuming project templates its own nebula configuration from the certificates and manifest produced here.
- **Lighthouse / runtime concepts.** Lighthouse, blocklist, firewall rules, listening ports — all of these are runtime config concerns and have no `nebula-cert` equivalent. They live in the downstream `config.yaml`, not here.
- **Revocation.** No blocklist management. See ADR-004.
- **Drift detection against remote hosts.** Manifest reflects what the tool last wrote, nothing more.
- **Multi-operator concurrency / locking.** Single-operator assumption.
- **CA rotation automation.** Manual procedure, to be documented separately when needed.
- **General-purpose sops wrapper.** Encryption is scoped strictly to this tool's artifacts.
- **A Terraform provider.** Evaluated and rejected; see ADR-001.

## Deferred capabilities (named so YAGNI is deliberate)

- Per-host `config.yaml` rendering.
- Short-lived certificates with auto-renewal.
- CA rotation workflow (multi-CA bundle, overlap windows).
- PKCS#11 / HSM-backed CAs.
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
- [`adr/009-host-identifier-vs-cert-name.md`](./adr/009-host-identifier-vs-cert-name.md) — why each `host` block has both a label (manifest key) and an optional `name` field (cert CN).
- [`adr/010-single-ca-per-config.md`](./adr/010-single-ca-per-config.md) — one CA per HCL file in v1; multi-CA configs deferred and additively reachable later.
- [`adr/011-output-blocks-are-directories.md`](./adr/011-output-blocks-are-directories.md) — why fan-out lives on the host as `output_dirs` rather than in a named `output` block.

## Operating model

1. Operator edits `nebula.hcl`.
2. Operator runs the CLI (`nebula-pki` to reconcile; `nebula-pki --dry-run` to preview; `nebula-pki check` to validate config).
3. CLI writes (or reuses) the CA, signs hosts, fans artifacts out to each host's `output_dirs`, updates `nebula-pki.json` (renameable via `storage.manifest_file`).
4. Manifest and (encrypted) artifacts are committed to git.
5. Downstream projects (Terraform, Ansible, custom scripts) read the artifacts directly from the per-provider output directories.

## Trust model

- The operator's workstation is the trust boundary. The CLI does not communicate over the network.
- Private key material is either left plaintext on disk (default) or encrypted via a storage backend the operator opts into.
- The age private key (when using the `sops` backend) is the highest-value secret in the system and lives outside the tool's responsibility.
- The CA private key, when in reference mode, is the operator's responsibility — the tool reads it but does not move, copy, or re-encrypt it.
