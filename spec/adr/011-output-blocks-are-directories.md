# Fan-out via `host.output_dirs`, not a named `output` block

## Status

accepted

## Context

The core fan-out feature lets the same host certificate land in multiple destination directories (one per downstream consumer — provider, project, environment). Earlier drafts of the schema had two distinct shapes for this:

1. **Templated filenames** inside a named `output` block:

    ```hcl
    output "hetzner" {
      dir      = "out/hetzner"
      crt_name = "{{.Host}}.crt"
      key_name = "{{.Host}}.key"
    }
    ```

2. **Directory-only** named `output` block, referenced by hosts:

    ```hcl
    output "hetzner" { dir = "out/hetzner" }

    host "app_01" {
      networks = ["10.42.1.10/16"]
      output   = ["hetzner"]
    }
    ```

Both are problematic.

### Templated filenames

`crt_name` / `key_name` create a **third identifier axis** in addition to the HCL label and the cert `name` settled by [ADR-009](./009-host-identifier-vs-cert-name.md). With templates, the on-disk filename can drift from both: an operator could template `"{{.Host}}-{{.Date}}.crt"`, hardcode `"app.crt"`, or otherwise produce a filename that no longer matches the cert CN. That defeats the invariant ADR-009 is meant to establish — "what's on disk matches what's in the cert".

`crt_name` / `key_name` also have **no analogue in `nebula-cert`**. The "HCL mirrors `nebula-cert` 1:1" principle in [ADR-001](./001-tooling-approach.md) is about cert *content* (name, networks, groups, duration, curve, version). File placement, fan-out, encryption wrapping, and manifest layout are `nebula-pki`'s own concerns with no upstream flag to mirror — but they should not introduce unnecessary surface either, and templated filenames serve a renaming use case nobody has asked for.

### Named `output` block referenced by hosts

Once filename templating is rejected, a named `output` block carries exactly one field, `dir`. The question is whether the label indirection is worth keeping:

- Operators repeat the directory string less often when many hosts share a destination.
- Two `output` blocks pointing at the same `dir` becomes a validation error — but that rule only exists because the block exists.
- Downstream tooling that consumes the manifest can group artifacts by the chosen output label.

Against:

- It adds a layer of indirection: the path-on-disk for a host is the result of a label lookup, not a literal string in the host block.
- The DRY benefit is weak; the directory string is typically short and repeated a handful of times. Modern editors make multi-line edits trivial.
- "Allow per-destination metadata in the future" (encryption recipients per output, file modes, post-write hooks) is **speculative** — none of those features is specified. YAGNI says: do not introduce a block as a placeholder for features that have not been designed.

## Decision

Fan-out is expressed **directly on the host** as a list of destination directories:

```hcl
host "lh_fra" {
  networks    = ["10.42.0.1/16"]
  output_dirs = ["out/hetzner", "out/shared"]
}
```

### Field semantics

- `host.output_dirs` is `list(string)`. Each entry is a **directory** — absolute, or relative to the config file. Trailing slashes are insignificant.
- For each entry, the CLI writes:
    - `<dir>/<host.name>.crt`
    - `<dir>/<host.name>.key`
    - `<dir>/<host.name>.png` (if `out_qr` is set on the host)
- Filenames are always derived from the cert `name`. `output_dirs` accepts directories, never full paths. There is no `crt_name`, `key_name`, or filename-template mechanism anywhere in the schema.
- `output_dirs` is mutually exclusive with `host.out_crt` / `host.out_key`.
- Two `output_dirs` entries on the same host pointing at the same directory is a validation error (after path normalisation). Two different hosts may share an entry — that is the fan-out shape, and the two certs occupy distinct `<host.name>.{crt,key}` files inside the directory.

### Per-host escape hatch

`host.out_crt` and `host.out_key` continue to accept a full path (directory + filename), giving an operator total control for unusual cases (e.g. legacy systems requiring a specific filename). They are single-host concerns and never participate in fan-out.

### What is not in the schema

No top-level `output` block. The filename-template feature (`crt_name`, `key_name`, `{{.Host}}` substitution) is not in the schema either.

## Consequences

### Positive

- The on-disk filename always equals `<host.name>.<ext>`. One identifier, one mental model. ADR-009's invariant is preserved by construction: `output_dirs` accepts directories, not paths, so filenames cannot drift.
- The HCL has one fewer block type. The path string in HCL is the literal path on disk; no two-step label lookup.
- Manifest entries are predictable: given a host and an entry from `output_dirs`, the consumer can compute the path without consulting the manifest.
- "Two destinations share a `dir`" failure mode collapses into a narrower local check (`host.output_dirs` deduplication), and only happens when a single host names the same directory twice.

### Negative

- Operators who fan out the same directory across many hosts repeat the directory string. With a handful of fan-out targets and dozens of hosts, this is editor-cursor territory.
- There is no operator-chosen short label for each destination directory. Downstream tooling that wanted to filter by label filters by directory path instead. In practice, downstream tooling reads files from a known directory and does not consult the manifest for that purpose.

### When a named `output` block would earn its place back

Reintroducing a named `output` block is a purely additive schema change: a new top-level block plus a new alternative on `host` (e.g. `host.output = "label"` alongside `host.output_dirs`). The bar for doing so is **per-destination metadata** that has no good home on the host itself. Concrete triggers, not hypotheticals:

- Per-destination encryption recipients (e.g. Hetzner ops have one age key, AWS ops another).
- Per-destination file modes or ownership.
- Per-destination post-write hooks (signing, upload, notification).
- Per-destination retention or pruning policy.

Until at least one of these is on the table with a worked example, fan-out stays inline on the host.

## Considered alternatives

### A. Templated filenames inside an `output` block

The earliest design (`crt_name`, `key_name`, `{{.Host}}`). Rejected: introduces a third identifier axis, contradicts ADR-009, and serves a use case no one has asked for.

### B. Allow `crt_name` / `key_name` but forbid templates (literal strings only)

Worse than (A). A literal filename inside an `output` block applies the same name to *every* host using it, which is incoherent — different certs would overwrite each other.

### C. Filename customisation field on `host`

```hcl
host "app_01" {
  filename    = "prod-app01"
  output_dirs = ["out/hetzner", "out/fly"]
}
```

Rejected. This is a renamed `name` field with worse semantics: the host already has a `name` that controls the cert CN, and having two name-like fields invites the exact confusion ADR-009 was meant to resolve. If the filename should differ from the label, that is what `host.name` is for.

### D. Named `output` block as a directory pointer

```hcl
output "hetzner" { dir = "out/hetzner" }

host "app_01" {
  output = ["hetzner"]
}
```

Rejected for v1. Once filename templating is out, the block carries one field and its only material benefit is per-destination metadata that has not been specified. The escape hatch documented above (reintroducing the block additively) keeps that door open without paying for it today.

## Links

- [ADR-001](./001-tooling-approach.md) — "1:1 with nebula-cert" framing; this ADR clarifies that the principle applies to cert content, not file placement.
- [ADR-009](./009-host-identifier-vs-cert-name.md) — label vs. cert name; this ADR keeps the on-disk filename aligned with the cert name by construction.
- [`../hcl-schema.md`](../hcl-schema.md) — schema reference.
