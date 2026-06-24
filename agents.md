# nebula-pki — operator & agent reference

Companion to [`readme.md`](./readme.md). This file holds operational detail, full option tables, file layout, schema-stability policy, and pointers into the spec. Agents and operators reading this should treat [`spec/`](./spec/readme.md) as the authoritative source.

## Scope recap

- Wraps `nebula-cert` (slackhq/nebula).
- HCL fields mirror `nebula-cert ca` and `nebula-cert sign` flags 1:1 with underscores.
- Adds: declarative config, per-host `output_dir` for custom certificate placement, optional at-rest encryption, a JSON manifest.
- One or more CAs per HCL file: a single unlabelled `ca {}`, or multiple labelled `ca "<label>" {}` blocks for rotation and multi-CA meshes ([ADR-015](./spec/adr/015-multiple-cas-per-config.md), supersedes [ADR-010](./spec/adr/010-single-ca-per-config.md)). Isolated environments may still use one file each.
- Emits a CA trust bundle for `pki.ca` and supports declarative CA rotation ([ADR-016](./spec/adr/016-ca-rotation-and-trust-bundles.md)), time-based renewal via `renew_before` ([ADR-017](./spec/adr/017-host-renewal-threshold.md)), and air-gapped `in_pub` signing ([ADR-018](./spec/adr/018-in-pub-air-gapped-signing.md)).
- Does not render `config.yaml`, does not push files (including during rotation), does not implement lighthouse/blocklist/firewall.

> Capability detail for the four areas above (multi-CA, rotation/bundle, `renew_before`, `in_pub`) currently lives in [`spec/`](./spec/readme.md) and the cited ADRs. The full option tables in this file are refreshed at the v0.1.0 cut (see [`spec/milestones/v0.1.md`](./spec/milestones/v0.1.md)); until then, treat `spec/hcl-schema.md` as authoritative where they differ.

## CLI

```sh
nebula-pki                # reconcile out/ with nebula.hcl
nebula-pki --dry-run      # preview only; write nothing
nebula-pki check          # parse + validate config; no I/O against out/. In CA reference mode, reads ca.cert_file / ca.key_file.
nebula-pki -c <path>      # alternate config path (default: ./nebula.hcl)
```

Exit codes: `0` on success or clean dry-run; `1` on validation/runtime error; `2` on usage error.

After each reconcile and `--dry-run` (including no-op runs), the tool prints to stderr the earliest actionable deadline — the soonest of a host entering its `renew_before` window or the expiry of any cert without a threshold — plus a "run again before `<date>`" hint. Advisory only; it changes no exit code and triggers no writes. See [`spec/adr/017-host-renewal-threshold.md`](./spec/adr/017-host-renewal-threshold.md).

Deferred:

- `nebula-pki show` — human summary of `out/nebula-pki.json`. Operators can `jq` the manifest until this lands. See [`spec/adr/008-cli-surface.md`](./spec/adr/008-cli-surface.md).

## Labels vs. cert names

By default, the block label is everything: manifest key, reference target, and cert common name.

```hcl
host "app_prod_01" {
  networks = ["10.42.1.10/16"]
}
# cert CN = "app_prod_01"; manifest key = "app_prod_01"
```

Set the optional `name` field only when label and CN should differ (cert needs characters HCL labels can't carry, or you want to evolve the two independently):

```hcl
host "edge_router" {
  name     = "edge-router.mesh"
  networks = ["10.42.2.1/16"]
}
# cert CN = "edge-router.mesh"; manifest key = "edge_router"
```

Default file paths use the **cert name**, not the label. Full rationale in [`spec/adr/009-host-identifier-vs-cert-name.md`](./spec/adr/009-host-identifier-vs-cert-name.md).

## References between blocks

The only cross-block reference is `host.ca` (with the CA marked `default = true` as the fallback when omitted), a plain string label selecting the signing CA when more than one CA exists ([ADR-015](./spec/adr/015-multiple-cas-per-config.md)). Hosts name their destination directory directly via `host.output_dir`. The schema avoids `hcl.EvalContext` because nothing is interpolated — references are bare labels, not traversal expressions. See [ADR-005](./spec/adr/005-hcl-schema-decision.md) and [ADR-020](./spec/adr/020-output-dir-per-host.md).

## Using an existing CA (reference mode)

```hcl
ca {
  cert_file = "/path/to/ca.crt"
  key_file  = "/path/to/ca.key"
}
```

In reference mode, generate-only fields (`name`, `duration`, `curve`, `version`, `encrypt`, `argon_*`, `out_*`) are rejected. The tool only reads the CA files; it never rewrites them.

On a run, nebula-pki loads the referenced pair and verifies it before recording anything: the certificate must be a CA (`IsCA`), its self-signature must verify, the key's curve must match the certificate, and the key must correspond to the certificate's public key. A missing `cert_file`/`key_file` is a hard error. An **expired** referenced CA is recorded anyway with a warning on stderr — the operator owns the CA in reference mode. The manifest records `ca.mode = "reference"` with the CA's fingerprint, validity window, and the referenced paths; `out/ca/` is never written. `nebula-pki check` additionally reads the referenced files and prints the CA fingerprint.

Reference-mode reconcile is idempotent: a second run against an unchanged referenced CA writes nothing (the manifest stays byte-identical). Pointing `cert_file`/`key_file` at a different CA updates the manifest's recorded fingerprint on the next run.

## Full CA options (generate mode)

```hcl
ca "label" {
  # Identity
  name              = "wiech-mesh"
  default           = true                   # default signing CA for hosts that omit host.ca

  # Validity
  duration          = "26280h"               # 3 years
  renew_before      = "720h"                 # re-sign hosts 30 days before expiry (inherited)

  # Rotation
  archived          = false                  # true → excluded from trust bundle; may not sign

  # Certificate format
  version           = 2                      # cert format 1 or 2
  curve             = "25519"                # or "P256"

  # Subordinate cert restrictions (validated per host)
  groups            = ["lighthouse", "app"]
  networks          = ["10.42.0.0/16"]
  unsafe_networks   = ["192.168.0.0/16"]

  # Key encryption (not yet implemented — planned for v0.2)
  encrypt           = true
  argon_memory      = 2097152
  argon_iterations  = 1
  argon_parallelism = 4

  # Output path overrides
  out_crt           = "out/ca/ca.crt"
  out_key           = "out/ca/ca.key"
  out_qr            = "out/ca/ca.png"
}
```

## Full host options

```hcl
host "router" {
  name            = "router.mesh"               # optional; defaults to label
  ca              = "my-ca"                     # signing CA label; omit to use the default CA
  networks        = ["10.42.2.1/16", "fd42::1/64"]
  unsafe_networks = ["192.168.10.0/24"]
  groups          = ["router"]
  duration        = "8760h"
  renew_before    = "48h"                       # overrides CA-level renew_before for this host
  output_dir      = "out/routers"               # destination directory; defaults to out/hosts
  in_pub          = "./pre-generated/router.pub"
  out_crt         = "out/router.crt"
  out_key         = "out/router.key"
  out_qr          = "out/router.png"
}
```

Path resolution for a host's cert/key (see [ADR-020](./spec/adr/020-output-dir-per-host.md)):

```
base      = output_dir              if set
          = <storage.out_dir>/hosts  otherwise
cert_path = Join(base, out_crt)     if out_crt set
          = Join(base, <name>.crt)  otherwise
key_path  = Join(base, out_key)     if out_key set
          = Join(base, <name>.key)  otherwise
```

`out_crt` and `out_key` compose with `output_dir` rather than overriding it; a bare filename stays in `base`, a relative sub-path nests inside it.

## Encryption backends

> **Not yet implemented.** The `encryption` block is parsed but rejected at runtime with a clear error message. These backends ship in v0.2. The schema documented here is final and stable.

### `none` (default)

```hcl
storage { encryption "none" {} }   # equivalent to omitting the block
```

### `sops` (built-in, in-process)

Behaves like the `sops` CLI. Every field is optional and maps 1:1 to a sops CLI flag (`age`→`--age`, `pgp`→`--pgp`, `kms`→`--kms`, `gcp_kms`→`--gcp-kms`, `azure_kv`→`--azure-kv`, `hc_vault_transit`→`--hc-vault-transit`, `shamir_threshold`→`--shamir-secret-sharing-threshold`, `config`→`--config`). When all key-type fields are empty, the sops library performs its standard upward search for `.sops.yaml` and applies whichever `creation_rules` match the output path.

```hcl
# Inline recipients — overrides .sops.yaml for files written here.
storage {
  encryption "sops" {
    age           = ["age1abc...", "age1def..."]
    output_suffix = ".enc"        # default
  }
}

# Empty block — defer entirely to .sops.yaml.
storage {
  encryption "sops" {}
}

# Mixed key types are fine; sops handles them transparently.
storage {
  encryption "sops" {
    age = ["age1abc..."]
    pgp = ["0CF71C98F51B70EBE5F4D615C0025195578345E2"]
  }
}
```

Uses the sops Go library; no `sops` binary required. Decrypt with the regular `sops` CLI, which resolves the same `.sops.yaml` rules.

### `external` (any command)

```hcl
storage {
  encryption "external" {
    encrypt_command = ["age", "-e", "-r", "age1abc...", "-o", "{{.Out}}", "{{.In}}"]
    decrypt_command = ["age", "-d", "-o", "{{.Out}}", "{{.In}}"]
    output_suffix   = ".age"
  }
}
```

The tool writes plaintext to a temp file, substitutes placeholders, runs the command, then deletes the temp file. `decrypt_command` is optional but recommended for future workflows that need to read encrypted material back.

## Custom output directory (`output_dir`)

```hcl
host "lh_fra" {
  networks   = ["10.42.0.1/16"]
  groups     = ["lighthouse"]
  output_dir = "out/hetzner"
}
```

`output_dir` is a single **directory**. Filenames default to `<host.name>.crt` / `.key`; override with `out_crt` / `out_key` (path components joined onto the directory). When omitted, files land in `<storage.out_dir>/hosts`. See [ADR-020](./spec/adr/020-output-dir-per-host.md).

## File layout

```
nebula/
  readme.md             # user-facing intro
  agents.md             # this file
  nebula.hcl            # your configuration
  spec/                 # authoritative specification
    readme.md
    hcl-schema.md
    hcl-schema.formal.json
    adr/
      001-tooling-approach.md
      002-state-and-artifact-layout.md
      003-encryption-strategy.md
      004-revocation-strategy.md
      005-hcl-schema-decision.md
      006-storage-backend-extensibility.md
      007-schema-evolution.md
      008-cli-surface.md
      009-host-identifier-vs-cert-name.md
      010-single-ca-per-config.md
      011-output-blocks-are-directories.md
      012-upstream-nebula-coupling.md
      013-atomic-artifact-writes.md
      014-flake-version-sync.md
  out/                  # generated; safe to commit when encryption is on
    nebula-pki.json     # manifest; rename via storage.manifest_file
    ca/
    hosts/              # default location for hosts without an `output_dir`
    <custom-dir>/       # any directory set via host.output_dir
```

## Manifest

`out/nebula-pki.json` is the single source of truth across runs. Schema highlights:

- `schema_version` — integer, currently `1`.
- `ca.mode` — `"generate"` or `"reference"`; includes fingerprint, validity, paths.
- `hosts` — map keyed by host label; each entry carries cert name, fingerprint, validity, the literal HCL `duration`, groups, networks, and `artifacts` (one entry per resolved destination directory with concrete `crt_path` and `key_path`).
- `encryption` — public backend identifier and parameters (no secret material).

Full schema in [`spec/adr/002-state-and-artifact-layout.md`](./spec/adr/002-state-and-artifact-layout.md).

## Schema stability policy

The HCL has **no version field today**. If a breaking change becomes necessary later:

- An optional top-level `nebula_pki { schema = 2 }` block will be introduced.
- Configs without it continue to parse as `schema = 1`.

The manifest already carries an explicit `schema_version` field from day one — downstream tooling parsing the manifest needs an unambiguous signal. See [`spec/adr/007-schema-evolution.md`](./spec/adr/007-schema-evolution.md).

## Status

Current release: **v0.0.10** (CA rotation + `renew_before`). Installable via Homebrew and Nix. The implementation tracks [`spec/`](./spec/readme.md). Version, supported platforms, and the pinned upstream Nebula version are surfaced via `nebula-pki --version` and the manifest's `generator.nebula_library_version` field. See [ADR-012](./spec/adr/012-upstream-nebula-coupling.md) for the upstream coupling policy.

**Not yet implemented**: `storage.encryption` (any backend). The parser accepts the block and reports a clear error — encryption ships in v0.2.

## Validation rules (selected)

- Duplicate `host` labels → error.
- Duplicate cert `name`s (after defaulting from labels) → error.
- Duplicate first-prefix overlay addresses across hosts → error.
- `ca` in reference mode with generate-only fields → error.
- `ca` reference mode with only one of `cert_file`/`key_file` → error.
- `ca` reference mode whose `cert_file`/`key_file` do not exist on disk → error (at reconcile/`check`, not parse time).
- `ca` reference mode whose files are not a coherent CA pair (not a CA, bad self-signature, curve/key mismatch) → error.
- A host's signing CA has `archived = true` → error (archived CAs may not sign).
- More than one `ca` block sets `default = true` → error.
- `host.ca` names a CA that is not declared → error.
- `host.groups` containing a group not in `ca.groups` (when restricted) → error.
- `host.networks` containing a prefix not contained by `ca.networks` (when restricted) → error.
- `host.unsafe_networks` containing a prefix not contained by `ca.unsafe_networks` (when restricted) → error.
- A CA's `renew_before` is ≥ its `duration` → error.
- A host's effective `renew_before` is ≥ its effective validity → error.

Full list in [`spec/hcl-schema.md`](./spec/hcl-schema.md#validation-rules).

## Further reading

- [`spec/readme.md`](./spec/readme.md) — authoritative project spec.
- [`spec/hcl-schema.md`](./spec/hcl-schema.md) — annotated HCL reference.
- [`spec/hcl-schema.formal.json`](./spec/hcl-schema.formal.json) — JSON Schema (2020-12).
- [`spec/adr/`](./spec/adr/) — architecture decisions.
- Upstream Nebula: <https://github.com/slackhq/nebula>.
