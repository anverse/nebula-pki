# HCL schema design

## Status

accepted

## Context

The CLI consumes a declarative configuration. We need to choose a config language and a schema shape that is ergonomic, unambiguous to validate, and closely aligned with the `nebula-cert` tool we wrap.

## Decision

The configuration language is **HCL2**. Parsed via `hashicorp/hcl/v2` and bound to Go structs with `gohcl`. The schema is intentionally a thin declarative skin over `nebula-cert`:

- One `ca` block ↔ `nebula-cert ca` (or reference an existing CA file).
- One `host` block per `nebula-cert sign` invocation.
- `storage`, `output`, and `encryption` blocks are tool-level concerns (where files land, how keys are protected at rest) and have no `nebula-cert` equivalent.

Field names mirror `nebula-cert` flag names with underscores: `-networks` → `networks`, `-unsafe-networks` → `unsafe_networks`, `-out-crt` → `out_crt`, etc. This is deliberate so that operators familiar with `nebula-cert` recognise the schema immediately and can correlate problems with upstream documentation.

Concepts that do not exist in `nebula-cert` are deliberately excluded:

- No `network` top-level block. Networks are per-host (Nebula's `-networks` is per-cert).
- No `is_lighthouse`. Lighthouses are a runtime concept, not a certificate attribute.
- No `blocklist_entry`. Blocklist is a runtime config concern; see ADR-004.
- No `group` top-level block. Group names are free-form strings; a CA can restrict the set via `ca.groups`.

Labelled blocks (`encryption "sops" {}`) are used where a backend or named target is needed, mirroring Terraform's resource-type pattern.

There are no cross-block references in v1. Fan-out to multiple destination directories is expressed inline on the host via `host.output_dirs` (a list of directory strings), not through a labelled `output` block referenced by name. This avoids implementing an `hcl.EvalContext` and keeps the JSON projection trivially equivalent to the HCL form. See [ADR-011](./011-output-blocks-are-directories.md) for the rationale and the conditions under which a named `output` block could be added back additively.

### Labels and the optional `name` field

The host identifier/CN split — single HCL label plus optional `name` field — is recorded separately in [ADR-009](./009-host-identifier-vs-cert-name.md). The short version: every `host` block has a single label that doubles as the manifest key and reference target; an optional `name` field overrides the certificate CN when label and CN should diverge. `output` blocks have only a label, since their identity is purely structural.

## Consequences

- The schema is small, predictable, and aligned with upstream Nebula vocabulary.
- The formal JSON Schema describes the post-parse object model. Any HCL-to-JSON conversion produces a document that validates against it.
- Adding a new `nebula-cert` flag to a future Nebula release is a one-line schema addition.
- Adding tool-level features (a second encryption backend, a new output template variable) is non-breaking.
- The schema can grow to accommodate features that `nebula-cert` itself does not have (e.g. PKCS#11 references, post-quantum curves) without violating its "thin skin" intent — as long as each new field maps to either a `nebula-cert` flag or a clearly tool-level concern.
- Schema versioning is **not** part of v1. See ADR-007 for the deferred but planned approach.
