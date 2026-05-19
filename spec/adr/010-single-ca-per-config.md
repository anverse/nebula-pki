# Single CA per configuration file

## Status

accepted

## Context

A `nebula.hcl` file describes a CA and the host certificates issued from it. A reasonable alternative would be to allow multiple CAs in a single file — typically one per environment (`dev`, `staging`, `prod`) — with each host bound to one of them. Operators coming from Terraform's workspace model or from "everything in one repo" patterns might expect this.

The question is whether v1 should support multi-CA configs.

## Decision

**v1 supports exactly one `ca` block per configuration file.** Operators who need multiple CAs use multiple HCL files and run `nebula-pki` once per file, distinguishing them via `-c <path>` and `storage.manifest_file`.

```sh
nebula-pki -c dev.hcl
nebula-pki -c prod.hcl
```

The schema enforces this: more than one `ca` block in a single file is a validation error.

## Why

### Simplicity wins the v1 trade

A single CA per file means:

- The manifest has a single CA root. No CA-keyed sub-trees.
- `host.ca = "<label>"` references are not needed; every host has exactly one CA to sign against.
- `output` blocks don't need a CA discriminator either.
- Validation rules around "host references undeclared CA", "two CAs share a name", "CA-restricted networks/groups apply to the right subset of hosts" do not exist.
- The CLI surface stays flat — no `--ca <label>` flag, no per-CA dry-run output.

The cost is paid by operators who *want* multiple CAs in one file. The workaround (multiple `*.hcl` files, one per CA) is supported, documented, and already needed for the multi-config-per-directory case (see [ADR-002](./002-state-and-artifact-layout.md) and the manifest-file override in [`hcl-schema.md`](../hcl-schema.md)).

### The use case is small and the workaround is good

Operators with multiple environments almost always want them isolated in other ways too: separate output directories, separate manifests, separate encryption recipients, separate review/approval flows. Splitting them into separate HCL files aligns with all of those instincts. A single file mixing `dev` and `prod` certs would be a foot-gun even if the schema allowed it.

For the rare case where a single human really does manage two CAs that share most other configuration (encryption recipients, output structure, host list shape), HCL doesn't have a great answer anyway — there's no template/macro layer in the language. Templating belongs in a higher tool (e.g. a small generator script) if it becomes a real need.

### Forward compatibility is preserved

When and if multi-CA configs become a justified feature, the migration is additive:

```hcl
# Future shape — not v1:
ca "dev" {
  name     = "dev-mesh"
  duration = "8760h"
}

ca "prod" {
  name     = "prod-mesh"
  duration = "26280h"
}

host "app_01" {
  ca       = "dev"          # required only when >1 ca block exists
  networks = ["10.99.0.10/16"]
}
```

Rules:

- A single unlabelled `ca { ... }` block continues to parse exactly as today.
- Labelled `ca "<label>" { ... }` blocks are a new shape — opting in by adding labels.
- `host.ca` is required only when more than one `ca` block exists.
- The manifest grows a `cas` map keyed by label; the existing single-CA `ca` object stays for back-compat (or `cas[0]` semantics are defined cleanly via a manifest schema bump).

None of this constrains the v1 implementation. The single-CA schema is a strict subset of any plausible future multi-CA schema.

## Considered alternatives

### A. Multi-CA from day one

```hcl
ca "dev"  { ... }
ca "prod" { ... }
host "app_01" { ca = "dev"; networks = [...] }
```

Rejected for v1 because:

- Adds validation surface (host references undeclared CA; CA label collisions; CA-restricted groups/networks per-host; multi-CA fan-out semantics).
- Adds manifest schema surface (CA sub-trees, per-host CA fingerprints already present but now non-trivially scoped).
- Adds CLI surface (per-CA dry-run output, per-CA error reporting).
- Solves a problem most operators don't have, and the workaround (multiple HCL files) is already needed for unrelated multi-config-per-directory reasons.

### B. Implicit "default" CA plus optional labelled CAs

```hcl
ca { name = "default-mesh" }       # used when host.ca is unset
ca "prod" { name = "prod-mesh" }
host "app_01" { networks = [...] }  # uses default
host "app_02" { ca = "prod"; ... }  # uses prod
```

Rejected because the implicit/explicit mix is confusing. If multi-CA support arrives, requiring `host.ca` whenever more than one CA exists is clearer.

## Consequences

- v1 is simpler to implement, validate, and document.
- Operators with multiple CAs maintain one HCL file per CA. The multi-config-per-directory pattern ([`hcl-schema.md`](../hcl-schema.md#multi-config-in-one-directory)) handles this cleanly via `storage.manifest_file`.
- The "one CA per file" rule is enforceable as a schema-level constraint, not a runtime one — fewer surprises.
- Future multi-CA support is unblocked: the upgrade path is additive and does not break existing single-CA configs.
- This ADR should be revisited if and when multiple users independently ask for in-file multi-CA support. Until then, it stays a YAGNI deferral.

## Links

- [ADR-007](./007-schema-evolution.md) — schema-evolution policy that would govern any future multi-CA change.
- [`hcl-schema.md`](../hcl-schema.md#multi-config-in-one-directory) — multi-config-per-directory pattern, the supported way to run multiple CAs today.
