# Manifest compactness — omit optional fields when absent

* Status: accepted
* Deciders: fw
* Date: 2026-06-17

## Context

The manifest (`nebula-pki.json`) is a git-committed artifact. Operators review
its diffs to understand what changed. With Go's default `encoding/json`
behaviour, nil slices serialise as `null` and absent-by-design values as
explicit JSON nulls, producing noise in every diff:

```json
"hosts": {
  "app-server": {
    "name": "app-server",
    "networks": ["10.0.1.5/16"],
    "groups": null,
    "unsafe_networks": null,
    "duration": null,
    ...
  }
}
```

Fields like `groups` and `unsafe_networks` are optional configuration that a
host may never use. Recording their absence as explicit `null` adds no
information and makes every host entry longer and every diff noisier.

The `Duration` field on `Host` and the `Dir` field on `Artifact` already carry
`omitempty` — this extension applies the same principle consistently.

## Decision

Optional fields are omitted from the JSON output when they are empty (nil
slice, empty string, false bool). Required fields — those the schema guarantees
to be non-zero for every valid record — never carry `omitempty`.

### Fields given `omitempty` now

| Struct | Field | Type | Reason it is optional |
|---|---|---|---|
| `manifest.Host` | `Groups` | `[]string` | most hosts belong to no groups |
| `manifest.Host` | `UnsafeNetworks` | `[]string` | very few hosts use unsafe routes |

`Duration` and `Artifact.Dir` already carry `omitempty` and are not changed.

### Fields that must NOT receive `omitempty`

| Field | Reason |
|---|---|
| `Networks` | required by the schema; always non-empty |
| `Artifacts` | every signed host has at least one artifact entry |
| `Name`, `Fingerprint`, `CAFingerprint` | required identity fields |
| `NotBefore`, `NotAfter` | required validity-window fields |

### Policy for future optional fields

New optional fields on host or CA records default to `omitempty`. Any field
where the distinction between _absent_ and _explicitly null/false_ must be
observable by a consumer must document that exception in the relevant ADR.

### Backward compatibility

Dropping a field from the JSON output is backward-compatible for any correct
consumer. Go's `encoding/json`, Python, Terraform's `jsondecode`, and `jq` all
treat an absent JSON key identically to a zero value when reading into a typed
structure. A consumer that checks for key _presence_ (rather than _value_) to
distinguish "not set" from "set to empty" is not a supported use pattern of the
manifest contract (see [ADR-007](./007-schema-evolution.md) on consumer
expectations).

This is not a `schema_version` bump: absent optional fields are a strict
subset of the previous output, and the change is applied before the first
tagged release that writes host records (v0.0.5 is untagged at the time of
this decision).

## Consequences

- Minimal manifests: a host with no groups and no unsafe_networks no longer
  carries `"groups": null, "unsafe_networks": null` in every diff — those
  lines simply do not appear.
- New optional fields follow the same rule by default, so the manifest stays
  clean as more optional fields are added (renew_before, ca, in_pub, …).
- Any field that needs `null`-vs-absent to be observable must justify the
  exception explicitly in its ADR.

## Links

* [ADR-002](./002-state-and-artifact-layout.md) — manifest schema, field rules.
* [ADR-007](./007-schema-evolution.md) — consumer expectations and manifest
  versioning policy.
