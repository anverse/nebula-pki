# Host identifier vs. certificate name

## Status

accepted

## Context

Each `host` block must answer two related but distinct questions:

1. **What's the local identifier?** The thing that appears as the manifest key and shows up in tool output.
2. **What's the certificate's common name?** The string that ends up inside the cert binary, that Nebula prints in logs, that operators see in firewall rules and troubleshooting output, and that `nebula-cert -name` sets.

For most hosts these can be the same string. But the two roles have different constraints and different natural rates of change, and conflating them removes options the operator may want later.

### What Terraform does, and why

Terraform splits resources into three parts:

```hcl
resource "aws_instance" "web" {       # type=aws_instance, address=web
  tags = { Name = "production-app" }  # real-world name lives in a field
}
```

- **Type** — schema discriminator. We have only one resource type (`host`), so this slot collapses.
- **Address** — local identifier used in references (`aws_instance.web.id`), state keys, plan output. Must be a valid HCL identifier.
- **Real-world name** — what gets sent to the cloud provider, typically constrained by the target system (DNS rules, uniqueness scopes, length).

The split exists because:

- The address is referenced from other HCL expressions and must be a syntactic identifier.
- The real-world name has different character rules and may need to change independently of the address.
- Renaming a Terraform address would otherwise force `state mv`; renaming the real-world name would otherwise force destruction and recreation.

All three reasons apply, in adapted form, to `nebula-pki`.

## Decision

Each `host` block has:

- A **label** (single HCL label, required): the local identifier. Used as the manifest key and as the target of cross-block references.
- A **`name` field** (optional, string): the certificate common name (`nebula-cert -name`). Defaults to the label when omitted.

```hcl
# Simple case — most hosts look like this:
host "app_01" {
  networks = ["10.42.1.10/16"]
}
# manifest key = "app_01"; cert CN = "app_01"

# Split case — when you need it:
host "app_prod_01" {
  name     = "app-prod-01.mesh.internal"
  networks = ["10.42.1.10/16"]
}
# manifest key = "app_prod_01"; cert CN = "app-prod-01.mesh.internal"
```

Default file paths use the **cert name**, not the label. This keeps filenames aligned with the cert content: a `.crt` file is always named after the cert it contains. [ADR-011](./011-output-blocks-are-directories.md) strengthens this into a hard invariant by removing the per-output filename template.

## Why this is worth the small complexity

### Different character constraints

HCL labels follow the regex `^[A-Za-z_][A-Za-z0-9_-]*$`. Certificate common names can contain dots, slashes, and other characters HCL labels can't. Without the split, operators couldn't name a cert `app-01.mesh.internal` (a perfectly reasonable Nebula CN) without dropping the dot.

### Different rates of change

- Operators may want to rename the HCL identifier (e.g. `app_01` → `app_primary` for code clarity) without re-issuing the cert and updating every consumer.
- Operators may want to rename the cert CN (e.g. add a `.mesh` suffix for log clarity) without churning every HCL reference and the manifest history.

Splitting decouples these.

### Operational visibility

The cert CN appears in Nebula daemon logs, in firewall match rules, in `nebula-cert print` output, and in any blocklist machinery. It needs to be human-readable to operators who may never read the HCL. The label, by contrast, lives entirely inside the configuration and tooling.

### Future cross-block references

The v1 schema has no cross-block references at all. If future features add them (e.g. a CRL-like list, per-host trust relationships, or a named `output` block referenced from hosts), those references must target a stable identifier — the label — not a mutable display name.

## Considered alternatives

### Label only, no `name` field

```hcl
host "app_01" { networks = ["10.42.1.10/16"] }
```

Simpler. Rejected because:

- HCL label character rules force cert CN choices, which is the wrong direction (the cert CN is operationally visible; the label is not).
- Renaming the label forces re-issuing the cert. The relationship should be one-way: changing the cert CN should re-issue; changing the label should not.

### Required `name` field

```hcl
host "app_01" {
  name     = "app_01"
  networks = ["10.42.1.10/16"]
}
```

Rejected because it imposes ceremony on the 80% case (label and CN identical) for the benefit of the 20%.

### Single `name` field, no label

```hcl
host {
  name     = "app-01.mesh"
  networks = ["10.42.1.10/16"]
}
```

Rejected because HCL block labels are the natural anchor for cross-block references and for diff-friendly manifest keys. Stripping them creates a worse experience for the common case and complicates the schema.

## Consequences

- Newcomers can ignore the `name` field entirely and the tool works as expected.
- Operators who need the split get it without re-architecting their configs.
- The manifest schema uses the label as the per-host key (stable across cert renames). The cert CN is recorded as a separate field.
- Default file paths use the cert name. This is documented in [`adr/002-state-and-artifact-layout.md`](./002-state-and-artifact-layout.md), [`adr/011-output-blocks-are-directories.md`](./011-output-blocks-are-directories.md), and [`hcl-schema.md`](../hcl-schema.md).
- Validation: no two `host` blocks may share a label; no two `host` blocks may share a cert name (after defaulting). Both rules are independent and both are enforced.

## Links

- [ADR-005](./005-hcl-schema-decision.md) — broader HCL schema decisions, including the choice of string-valued references over Terraform-style traversals.
- [`hcl-schema.md`](../hcl-schema.md) — schema reference with the `host` block table.
