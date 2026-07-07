# HCL schema reference

This document describes the user-facing HCL configuration consumed by the CLI. The formal machine-readable schema lives in [`hcl-schema.formal.json`](./hcl-schema.formal.json).

A configuration file is conventionally named `nebula.hcl`.

## Scope

The CLI is a thin declarative wrapper around `nebula-cert ca` and `nebula-cert sign`. Every block maps to flags of those commands. Concepts that do **not** belong to `nebula-cert` (lighthouses, blocklist, runtime config) are intentionally absent.

## Top-level blocks

| Block | Cardinality | Purpose |
|---|---|---|
| `ca` | 1..N | Certificate authority — either generated or referenced from existing files. Every `ca` block must carry a label: `ca "<label>" {}`. One or more labelled CAs enable CA rotation and multi-CA Nebula networks in a single file. See [ADR-015](./adr/015-multiple-cas-per-config.md). |
| `storage` | 0..1 | Default output directory, trust-bundle path, and encryption backend. |
| `host` | 0..N | A host certificate to sign. Maps 1:1 to `nebula-cert sign`. Selects a signing CA via `host.ca` when more than one CA exists. Each host's cert and key are written to a per-host `output_dir` (defaults to `<storage.out_dir>/hosts`). |

There is **no** `network`, `group`, `blocklist_entry`, or `is_lighthouse` block. Networks are declared per-host (Nebula `-networks` is per-cert), groups are free-form non-empty UTF-8 strings on each host (commas and surrounding whitespace forbidden — see validation rules), and lighthouse behaviour is decided in the runtime `config.yaml` that downstream projects render.

The signing-CA default is set with `default = true` on a `ca` block (see the `ca` reference below), not at the top level.

## Block reference

### `ca`

Defines a signing CA. Every `ca` block must carry a label: `ca "<label>" {}`. A file may declare one or more labelled CAs. An unlabelled `ca {}` block is a parse error. See [ADR-015](./adr/015-multiple-cas-per-config.md).

Each CA has two mutually exclusive modes:

- **Generate mode** — the CLI creates a new CA via `nebula-cert ca`.
- **Reference mode** — the CLI uses an existing CA key/cert on disk and only signs hosts against it.

| Field | Type | Required | Default | `nebula-cert ca` flag | Description |
|---|---|---|---|---|---|
| _label_ | identifier | **yes** | — | — | CA label. Required on every `ca` block. Unique within the file; identifier rules `^[A-Za-z_][A-Za-z0-9_-]*$`. The label is the manifest key in `cas` and the target of `host.ca`. |
| `default` | bool | no | `false` | — | Marks this CA as the default signing CA. Hosts that omit `host.ca` are signed by it. At most one CA may set `default = true`. See [ADR-015](./adr/015-multiple-cas-per-config.md). |
| `name` | string | yes in generate mode | — | `-name` | CA name. Ignored in reference mode (CA is read as-is). |
| `duration` | duration | no | `"8760h"` (1 year, matches `nebula-cert` default) | `-duration` | Validity. Generate mode only. |
| `version` | number | no | `2` | `-version` | Certificate format version (1 or 2). Generate mode only. |
| `curve` | string | no | `"25519"` | `-curve` | `"25519"` or `"P256"`. Generate mode only. |
| `groups` | list(string) | no | `[]` | `-groups` | Constrains which groups subordinate certs may declare. Applied to hosts signed by **this** CA. |
| `networks` | list(CIDR) | no | `[]` | `-networks` | Constrains which networks subordinate certs may declare. Applied to hosts signed by **this** CA. |
| `unsafe_networks` | list(CIDR) | no | `[]` | `-unsafe-networks` | Constrains routable subnets. Applied to hosts signed by **this** CA. |
| `encrypt` | bool | no | `false` | `-encrypt` | Encrypt the CA private key with a passphrase (Argon2). Generate mode only. |
| `argon_memory` | number | no | `2097152` | `-argon-memory` | KiB. |
| `argon_iterations` | number | no | `1` | `-argon-iterations` | |
| `argon_parallelism` | number | no | `4` | `-argon-parallelism` | |
| `renew_before` | duration | no | unset | — | Default renewal threshold for hosts signed by this CA. A host is re-signed when within this window of expiry. Overridden by `host.renew_before`. See [ADR-017](./adr/017-host-renewal-threshold.md). |
| `archived` | bool | no | `false` | — | When `true`, this CA's certificate is excluded from the emitted trust bundle and the CA may not sign hosts. Its manifest record is kept (archiving never deletes history). Used to stage the final step of a rotation. See [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md). |
| `out_crt` | string | no | `<storage.out_dir>/ca/<label>.crt` | `-out-crt` | Path for CA cert. Generate mode only. |
| `out_key` | string | no | `<storage.out_dir>/ca/<label>.key` | `-out-key` | Path for CA private key. Generate mode only. |
| `out_qr` | string | no | unset | `-out-qr` | Optional PNG QR. Generate mode only. |
| `cert_file` | string | no (yes for reference mode) | — | `-ca-crt` (on sign) | Path to an existing CA cert. Activates reference mode. |
| `key_file` | string | no (yes for reference mode) | — | `-ca-key` (on sign) | Path to an existing CA key. Activates reference mode. |

**Mode selection:** if either `cert_file` or `key_file` is set, both must be set, and reference mode is active for that CA. Otherwise generate mode is active.

**Generate-only fields** (`name` aside): `duration`, `version`, `curve`, `encrypt`, `argon_*`, `out_crt`, `out_key`, `out_qr`. Setting any of them in reference mode is an error.

#### Signing-CA selection

Each host resolves to exactly one signing CA:

1. `host.ca` if set;
2. else the CA marked `default = true`, if any;
3. else if exactly one CA is declared, that CA (no ambiguity);
4. else it is a validation error (ambiguous — name a CA or mark one default).

This mirrors Terraform's provider model: one CA is the default (here via `default = true`), the rest are aliases a host selects with `host.ca`, and a host that names nothing gets the default. Per-CA `groups` / `networks` / `unsafe_networks` restrictions are validated against each host **relative to the CA that signs it**. See [ADR-015](./adr/015-multiple-cas-per-config.md). For the rotation workflow built on this, see [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md) and the [rotation example](#ca-rotation-example) below.

### `storage`

Defaults applied to every host that does not override paths via `output` or `out_crt` / `out_key`. Also picks the encryption backend.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `out_dir` | string | no | `"out"` | Root directory for default-path artifacts. Relative paths resolve against the config file's directory. |
| `manifest_file` | string | no | `<out_dir>/nebula-pki.json` | Path for the manifest JSON. Relative paths resolve against the config file's directory; absolute paths are honoured. Override when sharing a working directory between multiple HCL configs. |
| `trust_bundle_file` | string | no | `<out_dir>/ca/bundle.crt` | Path for the emitted CA trust bundle — a concatenated PEM of every active (non-`archived`) CA certificate, suitable for `pki.ca` in each host's `config.yaml`. Always written, even with a single CA. Contains no key material. Membership is implicit (every non-archived CA); an explicit/multiple-bundle `bundle` block may be added additively later — see [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md). |
| `encryption` | block | no | `encryption "none" {}` | Encryption backend. |

The block label (`"none"`, `"sops"`, `"external"`) selects the backend. In the formal JSON Schema the label is projected as a `label` field, matching the `output` block convention.

#### `encryption "none" {}`

No fields. Private keys are written as plaintext.

#### `encryption "sops" { ... }`

Shells out to the `sops` binary. **The `sops` binary must be in PATH** when this backend is active — both for initial key generation (encrypt) and for any reconcile that signs hosts under an encrypted CA key (decrypt). Every field is optional and maps 1:1 to a `sops` CLI flag. When all key-type fields are empty, sops performs its standard upward search for `.sops.yaml` from the output file's directory and applies whichever `creation_rules` match. When at least one recipient field is set, those values are passed as explicit flags to sops and take precedence over `.sops.yaml` — same behaviour as `sops --encrypt --age ... --pgp ...`.

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
| `ca` | string | conditional | `-ca-crt`/`-ca-key` (selects which) | Label of the signing CA. Optional when the file has exactly one CA or a CA is marked `default = true` (omit to use the default, or set explicitly); required when the file has more than one CA and none is marked `default`. See [ADR-015](./adr/015-multiple-cas-per-config.md). |
| `networks` | list(CIDR) | yes | `-networks` | Overlay addresses for this host. Each entry is a full CIDR, e.g. `"10.42.0.1/16"`. |
| `groups` | list(string) | no | `-groups` | Free-form group tags. |
| `unsafe_networks` | list(CIDR) | no | `-unsafe-networks` | Subnets this host may route for. |
| `duration` | duration | no | `-duration` | Cert validity. Defaults to 1 second before CA expiry, matching `nebula-cert`. |
| `renew_before` | duration | no | — | Re-sign this host when within this window of `not_after`. Falls back to the signing CA's `renew_before`, then to no time-based renewal. Must be less than the effective validity. See [ADR-017](./adr/017-host-renewal-threshold.md). |
| `output_dir` | string | no | — | Destination directory for this host's cert and key. Relative paths resolve against the config file's directory; absolute paths are honoured. When omitted, defaults to `<storage.out_dir>/hosts`. See [ADR-020](./adr/020-output-dir-per-host.md). |
| `out_crt` | string | no | `-out-crt` | Cert path component. Joined onto `output_dir` when that is set; otherwise resolved relative to the config file. May be a bare filename (`nebula.crt`) or a relative sub-path (`certs/nebula.crt`). Defaults to `<host.name>.crt` within the base directory. |
| `out_key` | string | no | `-out-key` | Key path component. Same joining semantics as `out_crt`. Forbidden together with `in_pub` (no key is written). Defaults to `<host.name>.key` within the base directory. |
| `out_qr` | string | no | `-out-qr` | Path for the optional QR PNG, joined onto `output_dir` when set. QR contents are public; encryption is never applied. |
| `in_pub` | string | no | `-in-pub` | Path to a PEM **public key** exported by the device. When set, the CLI signs that public key and writes **only** the cert — no private key is generated or written, and no encryption applies. The key's curve must match the signing CA. Enables the "private key never leaves the device" pattern (mobile, HSM, separation of duties). Mutually exclusive with `out_key`. Mirrors `nebula-cert sign -in-pub`. See [ADR-018](./adr/018-in-pub-air-gapped-signing.md). |

#### Path resolution

For each host, the base directory and file paths are resolved as follows:

```
base      = output_dir              if set
            else <storage.out_dir>/hosts

cert_path = Join(base, out_crt)     if out_crt set
            else Join(base, <host.name>.crt)

key_path  = Join(base, out_key)     if out_key set
            else Join(base, <host.name>.key)

qr_path   = Join(base, out_qr)     if out_qr set  (cert only; no encryption)
```

`filepath.Join` concatenates and cleans. A bare filename in `out_crt` / `out_key` stays in `base`; a relative sub-path (`certs/node.crt`) nests inside it. When an absolute final path is needed, make `output_dir` absolute and use bare filenames in `out_crt` / `out_key` — combining an absolute `out_crt` with a set `output_dir` produces a joined result, not an override.

Encryption suffix is appended only to the **key** file (`.key` → `.key<suffix>`), and only when the active encryption backend is not `none`. Cert (`.crt`) and QR (`.png`) files are never encrypted and never suffixed.

When `in_pub` is set, no `.key` is written — only the `.crt` (and `.png`, if `out_qr`). The encryption suffix logic does not apply. See [ADR-018](./adr/018-in-pub-air-gapped-signing.md).

## Complete example

```hcl
ca "wiech-mesh" {
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
  name       = "lh-fra"
  networks   = ["10.42.0.1/16"]
  groups     = ["lighthouse"]
  output_dir = "out/hetzner"
}

host "app_01" {
  networks   = ["10.42.1.10/16"]
  groups     = ["app"]
  output_dir = "out/hetzner"
}

host "app_02" {
  networks   = ["10.42.1.11/16"]
  groups     = ["app"]
  output_dir = "out/aws"
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
ca "mesh" {
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

## CA rotation example

A worked rotation across a CA expiry, using two labelled CAs in one file. Each stage is a small edit to the same `nebula.hcl` followed by `nebula-pki`. The tool emits the artifacts; the operator distributes them and reloads hosts (the tool never pushes — see [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md)).

**Stage 0 — steady state, one CA.**

```hcl
ca "current" {
  name     = "mesh-2026"
  duration = "8760h"
  networks = ["10.42.0.0/16"]
}

host "app_01" { networks = ["10.42.1.10/16"] }   # only one CA, no host.ca needed
```

`out/ca/bundle.crt` contains just `current`.

**Stage 1 — add the new CA.** The bundle now carries both; ship `bundle.crt` to every host and reload (hosts now *trust* both CAs; certs still signed by `current`). Mark `current` as the default so existing hosts keep being signed by it without per-host edits.

```hcl
ca "current" {
  name     = "mesh-2026"
  duration = "8760h"
  networks = ["10.42.0.0/16"]
  default  = true                 # hosts without `ca` are signed by current
}

ca "next" {
  name     = "mesh-2027"
  duration = "8760h"
  networks = ["10.42.0.0/16"]     # same restrictions
}

host "app_01" { networks = ["10.42.1.10/16"] }
```

**Stage 2 — flip the signing CA.** Move the `default = true` marker from `current` to `next`. On the next run every defaulted host is re-signed under `next`; distribute the new host certs and reload. (Canary first by setting `ca = "next"` on a few hosts before moving the default.)

```hcl
ca "current" {
  name     = "mesh-2026"
  duration = "8760h"
  networks = ["10.42.0.0/16"]
}

ca "next" {
  name     = "mesh-2027"
  duration = "8760h"
  networks = ["10.42.0.0/16"]
  default  = true                 # was on current
}
```

**Stage 3 — archive the old CA.** Drop `current` from the bundle; ship the slimmer `bundle.crt` and reload. Delete the block (and key) once satisfied.

```hcl
ca "current" {
  name     = "mesh-2026"
  duration = "8760h"
  networks = ["10.42.0.0/16"]
  archived = true                 # excluded from bundle; may not sign
}
```

## Air-gapped (`in_pub`) example

For hosts whose private key must never leave the device — mobile, HSM-backed, or separation-of-duties. The device generates its own keypair (`nebula-cert keygen` on the device, or the Mobile Nebula app) and exports only the public key. The operator drops that `.pub` where the config points; `nebula-pki` signs it and writes a cert only. See [ADR-018](./adr/018-in-pub-air-gapped-signing.md).

```hcl
ca "mesh-2026" {
  name     = "mesh-2026"
  duration = "8760h"
}

host "alice_phone" {
  networks = ["10.42.5.20/16"]
  groups   = ["mobile"]
  in_pub   = "./inbox/alice_phone.pub"   # device-exported public key (non-secret)
  # no out_key — nebula-pki writes only alice_phone.crt
}
```

## Multi-config in one directory

A single HCL file may declare multiple CAs (see [ADR-015](./adr/015-multiple-cas-per-config.md)) — this is the right shape for **rotation**, where old and new CA are the same Nebula network in transition. For **isolated environments** (`dev`, `staging`, `prod`), prefer one HCL file per environment sharing the working directory: separate manifests, separate output directories, and separate review/approval flows align with how operators want environments kept apart.

Each config must own a distinct manifest, and the resolved artifact paths must not overlap between configs.

`dev.hcl`:

```hcl
ca "dev" { name = "dev-mesh" }

storage {
  out_dir       = "out/dev"
  manifest_file = "out/dev.nebula-pki.json"   # or "out/dev/nebula-pki.json"
}

host "app_01" { networks = ["10.99.0.10/16"] }
```

`prod.hcl`:

```hcl
ca "prod" { name = "prod-mesh" }

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
    wiech-mesh.crt
    wiech-mesh.key.enc
    bundle.crt
  hetzner/
    lh-fra.crt
    lh-fra.key.enc
    app_01.crt
    app_01.key.enc
  aws/
    app_02.crt
    app_02.key.enc
  hosts/
    router-edge.crt
    router-edge.key.enc
```

## Validation rules

CA and multi-CA:

- A configuration file declares zero `ca` blocks.
- A `ca` block has no label (unlabelled `ca {}` is a parse error; use `ca "<label>" {}`).
- Two `ca` blocks share a label.
- A `ca` label is not a valid identifier (`^[A-Za-z_][A-Za-z0-9_-]*$`).
- More than one `ca` block sets `default = true`.
- `host.ca` names a CA label that is not declared.
- A host's signing CA is ambiguous: the file has >1 CA, the host has no `host.ca`, and no CA is marked `default = true`.
- A host is signed by an `archived = true` CA (archived CAs may not sign).
- `ca` is in reference mode but only one of `cert_file` / `key_file` is set.
- `ca` is in reference mode and sets generate-only fields (`name`, `duration`, `curve`, `version`, `out_*`, `argon_*`, `encrypt`).

Hosts:

- Two `host` blocks share a label.
- Two `host` blocks (after `name` defaulting) share a certificate `name`.
- Two `host` blocks share an overlay address (the `Addr()` of the first prefix in `networks`, regardless of prefix length). `nebula-cert` cannot detect cross-host conflicts; catching them at config time avoids deploying a broken Nebula network.
- A `host.networks` entry is not a valid CIDR.
- A `host.duration` exceeds its signing CA's `not_after`.
- A `host` sets both `in_pub` and `out_key` (no key is written when signing a supplied public key).
- A `host.in_pub` file's public-key curve does not match its signing CA's curve (checked at reconcile/`check`, not parse time — the file must be read).
- `host.groups` references a group not permitted by its signing CA's `groups` (when that CA's `groups` is non-empty).
- `host.networks` contains a prefix not contained by any of its signing CA's `networks` prefixes (when that CA's `networks` is non-empty).
- `host.unsafe_networks` contains a prefix not contained by any of its signing CA's `unsafe_networks` prefixes (when that CA's `unsafe_networks` is non-empty).

Renewal:

- A host's effective `renew_before` (from `host.renew_before` or the signing CA's `renew_before`) is greater than or equal to the host's effective validity (`duration`, or CA-expiry-minus-1s when unset). See [ADR-017](./adr/017-host-renewal-threshold.md).

Groups and storage:

- Any `groups` entry (on `ca` or `host`) is empty, contains a comma, or contains leading/trailing whitespace. Group strings are otherwise free-form UTF-8; commas are forbidden because `nebula-cert`'s flag is comma-separated.
- Multiple `encryption` blocks in a single `storage`.

## References between blocks

The schema has exactly one kind of cross-block reference: a host names its signing CA by **label** via `host.ca` (with the CA marked `default = true` as the fallback when `host.ca` is omitted), introduced in [ADR-015](./adr/015-multiple-cas-per-config.md). This is a plain string label, not a traversal expression — the schema does not use `hcl.EvalContext`; see [ADR-005](./adr/005-hcl-schema-decision.md).

Hosts name their destination directory via `output_dir`. See [ADR-020](./adr/020-output-dir-per-host.md) for the rationale, path-resolution rules, and the conditions under which multi-directory fan-out would be reintroduced.

If a future field needs to reference another block (per-output encryption recipients, for example), it will be added by reintroducing a named `output` block alongside the inline form, following the same label-reference pattern as `host.ca`.

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
