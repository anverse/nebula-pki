# HCL schema reference

This document describes the user-facing HCL configuration consumed by the CLI. The formal machine-readable schema lives in [`hcl-schema.formal.json`](./hcl-schema.formal.json).

A configuration file is conventionally named `nebula.hcl`.

## Scope

The CLI is a thin declarative wrapper around `nebula-cert ca` and `nebula-cert sign`. Every block maps to flags of those commands. Concepts that do **not** belong to `nebula-cert` (lighthouses, blocklist, runtime config) are intentionally absent.

## Top-level blocks

| Block | Cardinality | Purpose |
|---|---|---|
| `ca` | exactly 1 | Certificate authority — either generated or referenced from existing files. One CA per file is a hard constraint in v1; see [ADR-010](./adr/010-single-ca-per-config.md). |
| `storage` | 0..1 | Default output directory and encryption backend. |
| `host` | 0..N | A host certificate to sign. Maps 1:1 to `nebula-cert sign`. Fan-out to multiple destination directories is configured per host via `output_dirs`. |

There is **no** `network`, `group`, `blocklist_entry`, or `is_lighthouse` block. Networks are declared per-host (Nebula `-networks` is per-cert), groups are free-form non-empty UTF-8 strings on each host (commas and surrounding whitespace forbidden — see validation rules), and lighthouse behaviour is decided in the runtime `config.yaml` that downstream projects render.

## Block reference

### `ca`

Defines the signing CA. Two mutually exclusive modes:

- **Generate mode** — the CLI creates a new CA via `nebula-cert ca`.
- **Reference mode** — the CLI uses an existing CA key/cert on disk and only signs hosts against it.

| Field | Type | Required | Default | `nebula-cert ca` flag | Description |
|---|---|---|---|---|---|
| `name` | string | yes in generate mode | — | `-name` | CA name. Rejected in reference mode (the CA name is read from the existing certificate). |
| `duration` | duration | no | `"8760h"` (1 year, matches `nebula-cert` default) | `-duration` | Validity. Generate mode only. |
| `version` | number | no | `2` | `-version` | Certificate format version (1 or 2). Generate mode only. |
| `curve` | string | no | `"25519"` | `-curve` | `"25519"` or `"P256"`. Generate mode only. |
| `groups` | list(string) | no | `[]` | `-groups` | Constrains which groups subordinate certs may declare. |
| `networks` | list(CIDR) | no | `[]` | `-networks` | Constrains which networks subordinate certs may declare. |
| `unsafe_networks` | list(CIDR) | no | `[]` | `-unsafe-networks` | Constrains routable subnets. |
| `encrypt` | bool | no | `false` | `-encrypt` | Encrypt the CA private key with a passphrase (Argon2). Generate mode only. |
| `argon_memory` | number | no | `2097152` | `-argon-memory` | KiB. |
| `argon_iterations` | number | no | `1` | `-argon-iterations` | |
| `argon_parallelism` | number | no | `4` | `-argon-parallelism` | |
| `out_crt` | string | no | `<storage.out_dir>/ca/ca.crt` | `-out-crt` | Path for CA cert. Generate mode only. |
| `out_key` | string | no | `<storage.out_dir>/ca/ca.key` | `-out-key` | Path for CA private key. Generate mode only. |
| `out_qr` | string | no | unset | `-out-qr` | Optional PNG QR. Generate mode only. |
| `cert_file` | string | no (yes for reference mode) | — | `-ca-crt` (on sign) | Path to an existing CA cert. Activates reference mode. |
| `key_file` | string | no (yes for reference mode) | — | `-ca-key` (on sign) | Path to an existing CA key. Activates reference mode. |

**Mode selection:** if either `cert_file` or `key_file` is set, both must be set, and reference mode is active. Otherwise generate mode is active.

### `storage`

Defaults applied to every host that does not override paths via `output` or `out_crt` / `out_key`. Also picks the encryption backend.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `out_dir` | string | no | `"out"` | Root directory for default-path artifacts. Relative paths resolve against the config file's directory. |
| `manifest_file` | string | no | `<out_dir>/nebula-pki.json` | Path for the manifest JSON. Relative paths resolve against the config file's directory; absolute paths are honoured. Override when sharing a working directory between multiple HCL configs. |
| `encryption` | block | no | `encryption "none" {}` | Encryption backend. |

The block label (`"none"`, `"sops"`, `"external"`) selects the backend. In the formal JSON Schema the label is projected as a `label` field, matching the `output` block convention.

#### `encryption "none" {}`

No fields. Private keys are written as plaintext.

#### `encryption "sops" { ... }`

Behaves like the `sops` CLI: every field is optional and maps 1:1 to a sops CLI flag. When all key-type fields are empty, the sops library performs its standard upward search for `.sops.yaml` and applies whichever `creation_rules` match the output path. When at least one is set, the inline values take precedence for files written by nebula-pki — same precedence as `sops -e --age ... --pgp ...` on the CLI.

| Field | Type | sops CLI flag | Description |
|---|---|---|---|
| `age` | list(string) | `--age` | Age recipient public keys. |
| `pgp` | list(string) | `--pgp` | PGP key fingerprints. |
| `kms` | list(string) | `--kms` | AWS KMS key ARNs. |
| `gcp_kms` | list(string) | `--gcp-kms` | GCP KMS resource IDs. |
| `azure_kv` | list(string) | `--azure-kv` | Azure Key Vault URLs. |
| `hc_vault_transit` | list(string) | `--hc-vault-transit` | Vault Transit URIs. |
| `shamir_threshold` | number | `--shamir-secret-sharing-threshold` | Threshold for Shamir secret sharing. |
| `config` | string | `--config` | Explicit `.sops.yaml` path. Defaults to upward search from each output file. |
| `output_suffix` | string | — | nebula-pki-specific. Default `".enc"`. |

When the block is left empty (`encryption "sops" {}`), nebula-pki relies entirely on `.sops.yaml`. This is the recommended setup when an operator already runs sops for other secrets.

#### `encryption "external" { ... }`

| Field | Type | Required | Description |
|---|---|---|---|
| `encrypt_command` | list(string) | yes | Argv. `{{.In}}` / `{{.Out}}` placeholders supported. |
| `decrypt_command` | list(string) | no | Inverse. Recommended. |
| `output_suffix` | string | no | Default `".enc"`. |

### `host`

Each `host` block produces one `nebula-cert sign` invocation. The simplest form is:

```hcl
host "app_01" {
  networks = ["10.42.1.10/16"]
}
```

The block label (`app_01` above) is the **HCL identifier**: the manifest key and the target of cross-block references. The certificate's common name defaults to the label, so most hosts need nothing more.

Set the optional `name` field when the certificate CN needs characters HCL labels cannot represent (e.g. dots), or when the manifest key and the operationally-visible cert name should evolve independently. Full rationale in [ADR-009](./adr/009-host-identifier-vs-cert-name.md).

| Field | Type | Required | `nebula-cert sign` flag | Description |
|---|---|---|---|---|
| _label_ | identifier | yes | — | HCL identifier; manifest key. Conventionally snake_case. |
| `name` | string | no (defaults to label) | `-name` | Certificate common name. Use when label and CN should differ. |
| `networks` | list(CIDR) | yes | `-networks` | Overlay addresses for this host. Each entry is a full CIDR, e.g. `"10.42.0.1/16"`. |
| `groups` | list(string) | no | `-groups` | Free-form group tags. |
| `unsafe_networks` | list(CIDR) | no | `-unsafe-networks` | Subnets this host may route for. |
| `duration` | duration | no | `-duration` | Cert validity. Defaults to 1 second before CA expiry, matching `nebula-cert`. |
| `out_crt` | string | no | `-out-crt` | Override cert output path. |
| `out_key` | string | no | `-out-key` | Override key output path. |
| `out_qr` | string | no | `-out-qr` | Path for the optional QR PNG. When `output_dirs` is set, the QR is fanned out symmetrically with the cert/key: a `<dir>/<host.name>.png` is written to each entry, and the `out_qr` value is treated as a flag (any non-empty string enables QR generation; the path itself is ignored in fan-out mode). When `out_crt`/`out_key` are used instead, `out_qr` is taken verbatim. QR contents are public; encryption is never applied. |
| `in_pub` | string | no | `-in-pub` | If set, the CLI does not generate a key — it signs the provided public key. Mirrors `nebula-cert -in-pub`. |
| `output_dirs` | list(string) | no | — | Destination directories. The cert/key is written to each as `<dir>/<host.name>.crt` and `<dir>/<host.name>.key`. Filenames are always derived from the cert `name` — entries are directories, not full paths. Mutually exclusive with `out_crt`/`out_key`. See [ADR-011](./adr/011-output-blocks-are-directories.md). |

#### Path resolution order

For each host, output paths are resolved as follows:

1. If `out_crt` / `out_key` are set, they are used verbatim (relative to config file). This is the per-host escape hatch and controls both directory and filename. `out_qr`, when set, is also used verbatim.
2. Else if `output_dirs` is set, paths are computed per entry: `<dir>/<host.name>.crt` and `<dir>/<host.name>.key`. When `out_qr` is also set (any non-empty value), a `<dir>/<host.name>.png` is written alongside.
3. Else paths default to `<storage.out_dir>/hosts/<host.name>.crt` and `<storage.out_dir>/hosts/<host.name>.key`. When `out_qr` is set, a sibling `<host.name>.png` is written in the same directory.

Encryption suffix is appended only to the **key** file (`.key` → `.key<suffix>`), and only when the active encryption backend is not `none`. Cert (`.crt`) and QR (`.png`) files are never encrypted and never suffixed.

## Complete example

```hcl
ca {
  name     = "wiech-mesh"
  duration = "26280h"   # 3 years
  curve    = "25519"
}

storage {
  out_dir = "out"

  encryption "sops" {
    age = ["age1xyz..."]
  }
}

host "lh_fra" {
  name        = "lh-fra"
  networks    = ["10.42.0.1/16"]
  groups      = ["lighthouse"]
  output_dirs = ["out/hetzner", "out/shared"]
}

host "app_01" {
  networks    = ["10.42.1.10/16"]
  groups      = ["app"]
  output_dirs = ["out/hetzner"]
}

host "app_02" {
  networks    = ["10.42.1.11/16"]
  groups      = ["app"]
  output_dirs = ["out/aws"]
}

host "router_edge" {
  name            = "router-edge"
  networks        = ["10.42.2.1/16"]
  unsafe_networks = ["192.168.10.0/24"]
  groups          = ["router"]
  # Falls back to default path under storage.out_dir/hosts/
}
```

## Reference-mode example

```hcl
ca {
  cert_file = "../existing-pki/ca.crt"
  key_file  = "../existing-pki/ca.key"
}

storage {
  out_dir = "out"
}

host "new_app" {
  networks = ["10.42.3.1/16"]
  groups   = ["app"]
}
```

## Multi-config in one directory

A single HCL file describes exactly one CA. To run multiple CAs (typically one per environment — `dev`, `staging`, `prod`), use one HCL file per CA and let them share the working directory. This is the **supported way to manage multiple CAs in v1**; see [ADR-010](./adr/010-single-ca-per-config.md).

Each config must own a distinct manifest, and the per-host `output_dirs` entries must point at non-overlapping directories.

`dev.hcl`:

```hcl
ca { name = "dev-mesh" }

storage {
  out_dir       = "out/dev"
  manifest_file = "out/dev.nebula-pki.json"   # or "out/dev/nebula-pki.json"
}

host "app_01" { networks = ["10.99.0.10/16"] }
```

`prod.hcl`:

```hcl
ca { name = "prod-mesh" }

storage {
  out_dir       = "out/prod"
  manifest_file = "out/prod.nebula-pki.json"
}

host "app_01" { networks = ["10.42.0.10/16"] }
```

Run each independently:

```sh
nebula-pki -c dev.hcl
nebula-pki -c prod.hcl
```

The manifest's `config_path` field records which HCL file produced it; a future `nebula-pki check` will warn when a manifest is overwritten by a different config.

## Resulting artifacts (first example)

```
out/
  nebula-pki.json
  ca/
    ca.crt
    ca.key.enc
  hetzner/
    lh-fra.crt
    lh-fra.key.enc
    app_01.crt
    app_01.key.enc
  aws/
    app_02.crt
    app_02.key.enc
  shared/
    lh-fra.crt
    lh-fra.key.enc
  hosts/
    router-edge.crt
    router-edge.key.enc
```

## Validation rules

- More than one `ca` block in a single configuration file (see [ADR-010](./adr/010-single-ca-per-config.md)).
- Two `host` blocks share a label.
- Two `host` blocks (after `name` defaulting) share a certificate `name`.
- Two `host` blocks share an overlay address (the `Addr()` of the first prefix in `networks`, regardless of prefix length). `nebula-cert` cannot detect cross-host conflicts; catching them at config time avoids deploying a broken mesh.
- A `host.networks` entry is not a valid CIDR.
- A `host.duration` exceeds the active CA's `not_after`.
- A `host` sets both `out_crt`/`out_key` and `output_dirs`.
- A `host.output_dirs` lists the same directory twice (entries deduplicated by normalised path).
- `ca` is in reference mode but only one of `cert_file` / `key_file` is set.
- `ca` is in reference mode and sets generate-only fields (`name`, `duration`, `curve`, `version`, `out_*`, `argon_*`, `encrypt`).
- Multiple `encryption` blocks in a single `storage`.
- `host.groups` references a group not permitted by `ca.groups` (when `ca.groups` is non-empty).
- Any `groups` entry (on `ca` or `host`) is empty, contains a comma, or contains leading/trailing whitespace. Group strings are otherwise free-form UTF-8; commas are forbidden because `nebula-cert`'s flag is comma-separated.
- `host.networks` contains a prefix not contained by any `ca.networks` prefix (when `ca.networks` is non-empty).
- `host.unsafe_networks` contains a prefix not contained by any `ca.unsafe_networks` prefix (when `ca.unsafe_networks` is non-empty).

## References between blocks

There are no cross-block references in the v1 schema. Hosts name their destination directories directly via `output_dirs`. See [ADR-011](./adr/011-output-blocks-are-directories.md) for the rationale and the conditions under which a named `output` block could be added back additively.

If a future field needs to reference another block (per-output encryption recipients, for example), it will be added by reintroducing a named block alongside the inline form rather than turning paths into traversal expressions. The schema does not use `hcl.EvalContext`; see [ADR-005](./adr/005-hcl-schema-decision.md).

## Labels vs. names (worked example)

```hcl
host "app_prod_01" {              # label only; cert CN = "app_prod_01"
  networks = ["10.42.1.10/16"]
}

host "app_prod_02" {
  name     = "app-prod-02.mesh"   # cert CN differs from label
  networks = ["10.42.1.11/16"]
}
```

The label is the manifest key and the reference target. The `name` is what ends up inside the cert and what appears in Nebula's logs. Rationale in [ADR-009](./adr/009-host-identifier-vs-cert-name.md).

## Schema evolution

The HCL has no version field today. If a breaking change becomes necessary, a forward-compatible mechanism is introduced at that point: a top-level `nebula_pki { schema = 2 }` block. Configs without it default to `schema = 1`. This avoids forcing an explicit version on day-one users while leaving a clear migration door open. The manifest already carries an explicit `schema_version`; see [`adr/002-state-and-artifact-layout.md`](./adr/002-state-and-artifact-layout.md) and [`adr/007-schema-evolution.md`](./adr/007-schema-evolution.md).
