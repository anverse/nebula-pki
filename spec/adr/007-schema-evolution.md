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
