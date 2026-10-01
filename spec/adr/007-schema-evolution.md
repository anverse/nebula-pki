# Schema evolution and breaking changes

## Status

accepted

## Context

The HCL schema will evolve. Some changes will be additive (new optional fields) and trivially backward-compatible. Others will be breaking — a renamed field, a removed block, semantics change. We need a policy that:

- Avoids forcing day-one users to write boilerplate they do not need.
- Gives a clear migration path when breaking changes happen.
- Is honest about the cost of breaking changes for downstream users (this is infrastructure tooling; downstream is "any project that consumes the artifacts and any operator who maintains a `nebula.hcl`").

## Decision

### v1: no explicit schema version field in HCL

The HCL configuration carries **no** top-level `version` or `nebula_pki` block in v1. Reasoning:

- It is uniform pain for everyone, paying for a problem that may not arrive.
- Adding it later is itself a backward-compatible change (see below).
- The manifest already has `schema_version` for the on-disk format, which is the place breaking changes are most likely to affect consumers first.

### Compatibility policy until a breaking change is needed

- Additive fields with sensible defaults: ship in any release.
- Renamed fields: support both names for at least one release with a deprecation warning, then remove.
- Removed fields / changed semantics: this is the trigger to introduce schema versioning.

> **Amendment (2026-07-19).** The trigger above applies **post-1.0**. While the tool is pre-1.0 with a single operator, removals may ship directly in a `v0.1.x` release without the schema block, provided the parse error for the removed form names the exact rewrite. Originally planned for [ADR-024](./024-rename-host-to-cert.md), [ADR-025](./025-ca-references.md) and [ADR-026](./026-trust-bundle-block.md); all three ship under the experimental-stage amendment below instead.

> **Amendment (2026-09-26) — experimental stage.** Until the tool is used in production (expected around v0.2), nebula-pki is **experimental**: its purpose in this phase is finding the best naming and shape, so breaking changes ship freely with **no migration path**. Specifically, while experimental:
>
> - Renamed or removed HCL keywords/fields are simply no longer accepted; the generic HCL decode error ("Unsupported block type" / "Unsupported argument") is sufficient. No targeted parse error naming the rewrite is required (this relaxes the 2026-07-19 amendment above).
> - Manifest field renames and on-disk layout changes ship **without** a `schema_version` bump and without read-side migration of older manifests. An existing `out/` tree may need to be regenerated from scratch.
> - Changelog / readme upgrade notes are optional.
>
> The 2026-07-19 policy (rewrite-naming parse errors) and the compatibility policy above resume once the tool is declared production-ready. Applied by [ADR-024](./024-rename-host-to-cert.md) (`host`→`cert`, manifest `hosts`→`certs`, `out/hosts/`→`out/certs/`), [ADR-025](./025-ca-references.md) (string `cert.ca`), and [ADR-026](./026-trust-bundle-block.md) (`archived`, `storage.trust_bundle_file`, implicit bundle).

### When a breaking change becomes necessary

Introduce a top-level optional block:

```hcl
nebula_pki {
  schema = 2
}
```

- Absent → treated as `schema = 1` (the current shape).
- Present and recognised → CLI parses according to that schema version.
- Present and unrecognised → CLI exits with a clear "this binary supports schema versions X..Y, config requires Z; upgrade or pin" message.

This block is deliberately namespaced (`nebula_pki`, not just `version`) to avoid clashing with any future Nebula-cert mirrored field.

### Manifest versioning

The manifest (default `nebula-pki.json`) carries `schema_version` from day one. This is non-negotiable: consumers read the manifest programmatically, so breaking changes to the manifest must be detectable without parsing the file deeply. Manifest schema version is independent of HCL schema version.

## Consequences

- Day-one configs are clean and version-free.
- Future breaking change is well-defined and signposted.
- The manifest leads schema versioning by a notch, because the manifest is the consumer-facing contract.
- Implementations of consumers (Terraform projects, scripts) should check `nebula-pki.json#/schema_version` before relying on its structure.
- This ADR will be revisited the first time we contemplate a breaking change; we may discover the proposed mechanism needs refining before the actual cut-over.
