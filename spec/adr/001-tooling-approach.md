# Tooling approach: custom Go CLI

* Status: accepted
* Deciders: fw
* Date: 2026-05-17

## Context and Problem Statement

Provisioning a [slackhq/nebula](https://github.com/slackhq/nebula) Nebula network requires generating a CA, signing per-host certificates, optionally encrypting key material at rest, and feeding the resulting files into several downstream Terraform projects. The current shell-script approach is hard to read and evolve. We need a single declarative workflow that scales beyond a handful of hosts and integrates cleanly with the rest of the infrastructure repo.

## Decision Drivers

* Declarative configuration the operator can review and diff.
* First-class artifacts on disk (so `nebula-cert` and other tools can still operate on them directly).
* Encrypted private keys at rest, with optional opt-in for users who do not want encryption.
* Reusable across multiple Terraform projects via simple `file()` reads.
* Minimum maintenance burden for a single-operator project.
* No new long-running services or agents.

## Considered Options

* A. Continue with shell scripts.
* B. Custom Terraform provider for Nebula.
* C. Existing Terraform provider for Nebula.
* D. Custom Go CLI wrapping the `slackhq/nebula/cert` library.

## Decision Outcome

Chosen option: **D. Custom Go CLI**, because it is the simplest tool that satisfies all decision drivers while keeping artifacts as ordinary files on disk and avoiding the impedance mismatch between Terraform's "everything in state" model and Nebula's file-oriented workflow.

### Positive Consequences

* Private key material can live exclusively in files (encrypted at rest), never in any state blob.
* `nebula-cert` and other Nebula tooling remain usable against the same artifacts.
* Distribution and integration are trivial: downstream projects consume files.
* Encryption is pluggable, so users can opt out without losing core functionality.
* Single static binary; no plugin system or external runtime dependencies in the default build.

### Negative Consequences

* State, diff, and idempotency logic must be implemented locally rather than inherited from Terraform. The CLI surface itself stays small (default reconcile + `--dry-run` + `check`); see [ADR-008](./008-cli-surface.md).
* No ecosystem of consumers; this is purpose-built tooling.
* Maintenance falls entirely on us.

## Pros and Cons of the Options

### A. Continue with shell scripts

* Good, because it already works.
* Bad, because readability and maintainability have degraded as features accreted.
* Bad, because revocation and idempotency are not modelled.

Rejected because we have outgrown it; this ADR exists precisely to replace it.

### B. Custom Terraform provider for Nebula

* Good, because we inherit HCL parsing, plan/apply UX, state, and drift detection.
* Good, because outputs integrate naturally with `terraform_remote_state` consumers.
* Bad, because Terraform's model wants secret material in state. Either we leak private keys into state (the `tls` provider pattern, with all its known pitfalls) or we contort the provider to write files out-of-band — at which point the abstraction fights us.
* Bad, because once keys are in state, the operator can no longer use `nebula-cert` directly against them without an export step.
* Bad, because writing a provider is multi-week work and we would maintain it indefinitely.

Rejected because the impedance mismatch is fundamental, not incidental.

### C. Existing Terraform provider for Nebula

* Good, because zero maintenance.
* Bad, because as of 2026-05-17 no maintained Terraform provider exists for slackhq/nebula. The Terraform Registry contains providers named "nebula" for unrelated products (Lacework Nebula, OpenNebula). GitHub search returns no maintained `terraform-provider-nebula` targeting slackhq/nebula.

Rejected because the option does not exist.

### D. Custom Go CLI wrapping `slackhq/nebula/cert`

* Good, because the upstream Go package exposes the exact primitives we need.
* Good, because we control the artifact layout, the encryption story, and the manifest format.
* Good, because the tool can stay small (~hundreds of lines, not thousands).
* Bad, because we re-implement plan/diff/idempotency.
* Bad, because no shared ecosystem.

Accepted.

## Links

* [slackhq/nebula](https://github.com/slackhq/nebula)
* [`slackhq/nebula/cert` package](https://pkg.go.dev/github.com/slackhq/nebula/cert)
* [ADR-008](./008-cli-surface.md) — CLI surface (default reconcile action vs Terraform-style verbs).
* Supersedes the previous shell-script approach captured in `nebula_generate.sh` and `nebula_restore.sh`.
