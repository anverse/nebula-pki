# HCL schema reference

This document describes the user-facing HCL configuration consumed by the CLI. The formal machine-readable schema lives in [`hcl-schema.formal.json`](./hcl-schema.formal.json).

A configuration file is conventionally named `nebula.hcl`.

## Scope

The CLI is a thin declarative wrapper around `nebula-cert ca` and `nebula-cert sign`. Every block maps to flags of those commands. Concepts that do **not** belong to `nebula-cert` (lighthouses, blocklist, runtime config) are intentionally absent.

## Top-level blocks

| Block | Cardinality | Purpose |
|---|---|---|
| `ca` | 1..N | Certificate authority — either generated or referenced from existing files. Every `ca` block must carry a label: `ca "<label>" {}`. One or more labelled CAs enable CA rotation and multi-CA Nebula networks in a single file. See [ADR-015](./adr/015-multiple-cas-per-config.md). |
| `trust_bundle` | 0..N | A CA trust bundle for `pki.ca`: explicit membership via `ca_refs`, its path (default `<out_dir>/bundles/<label>.crt`), and its own `link_crt` fan-out. Without any block no bundle is written. See [ADR-026](./adr/026-trust-bundle-block.md). |
| `storage` | 0..1 | Default output directory, manifest path, and encryption backend. |
| `cert` | 0..N | A certificate to sign — typically one `cert` block per Nebula node. Maps 1:1 to `nebula-cert sign`. Selects a signing CA via `cert.ca` when more than one CA exists. Each cert and its key are written to the cert's `output_dir` (defaults to `<storage.out_dir>/certs`). |

There is **no** `network`, `group`, `blocklist_entry`, or `is_lighthouse` block. Networks are declared per-cert (Nebula `-networks` is per-cert), groups are free-form non-empty UTF-8 strings on each cert (commas and surrounding whitespace forbidden — see validation rules), and lighthouse behaviour is decided in the runtime `config.yaml` that downstream projects render.

The signing-CA default is set with `default = true` on a `ca` block (see the `ca` reference below), not at the top level.

## Block reference

### `ca`

Defines a signing CA. Every `ca` block must carry a label: `ca "<label>" {}`. A file may declare one or more labelled CAs. An unlabelled `ca {}` block is a parse error. See [ADR-015](./adr/015-multiple-cas-per-config.md).

Each CA has two mutually exclusive modes:

- **Generate mode** — the CLI creates a new CA via `nebula-cert ca`.
- **Reference mode** — the CLI uses an existing CA key/cert on disk and only signs certs against it.

| Field | Type | Required | Default | `nebula-cert ca` flag | Description |
|---|---|---|---|---|---|
| _label_ | identifier | **yes** | — | — | CA label. Required on every `ca` block. Unique within the file; identifier rules `^[A-Za-z_][A-Za-z0-9_-]*$`. The label is the manifest key in `cas` and the target of `cert.ca`. |
| `default` | bool | no | `false` | — | Marks this CA as the default signing CA. Certs that omit `cert.ca` are signed by it. At most one CA may set `default = true`. See [ADR-015](./adr/015-multiple-cas-per-config.md). |
| `name` | string | yes in generate mode | — | `-name` | CA name. Ignored in reference mode (CA is read as-is). |
| `duration` | duration | no | `"8760h"` (1 year, matches `nebula-cert` default) | `-duration` | Validity. Generate mode only. |
| `version` | number | no | `2` | `-version` | Certificate format version (1 or 2). Generate mode only. |
| `curve` | string | no | `"25519"` | `-curve` | `"25519"` or `"P256"`. Generate mode only. |
| `groups` | list(string) | no | `[]` | `-groups` | Constrains which groups subordinate certs may declare. Applied to certs signed by **this** CA. |
| `networks` | list(CIDR) | no | `[]` | `-networks` | Constrains which networks subordinate certs may declare. Applied to certs signed by **this** CA. |
| `unsafe_networks` | list(CIDR) | no | `[]` | `-unsafe-networks` | Constrains routable subnets. Applied to certs signed by **this** CA. |
| `encrypt` | bool | no | `false` | `-encrypt` | Encrypt the CA private key with a passphrase (Argon2). Generate mode only. |
| `argon_memory` | number | no | `2097152` | `-argon-memory` | KiB. |
| `argon_iterations` | number | no | `1` | `-argon-iterations` | |
| `argon_parallelism` | number | no | `4` | `-argon-parallelism` | |
| `renew_before` | duration | no | unset | — | Default renewal threshold for certs signed by this CA. A cert is re-signed when within this window of expiry. Overridden by `cert.renew_before`. See [ADR-017](./adr/017-cert-renewal-threshold.md). |
| `out_crt` | string | no | `<storage.out_dir>/ca/<label>.crt` | `-out-crt` | Path for CA cert. Generate mode only. |
| `out_key` | string | no | `<storage.out_dir>/ca/<label>.key` | `-out-key` | Path for CA private key. Generate mode only. |
| `out_qr` | string | no | unset | `-out-qr` | Optional PNG QR. Generate mode only. |
| `cert_file` | string | no (yes for reference mode) | — | `-ca-crt` (on sign) | Path to an existing CA cert. Activates reference mode. |
| `key_file` | string | no (yes for reference mode) | — | `-ca-key` (on sign) | Path to an existing CA key. Activates reference mode. |
| `link_crt` | list(string) | no | `[]` | — | Directories where a relative symlink to this CA's cert should be placed. Each entry is a directory path; the symlink filename is `<label>.crt` (or `basename(out_crt)` when set). Symlink targets are relative (safe to commit to git). Parent directories are created if absent. Correct symlinks are no-ops; broken or wrong-target symlinks are recreated; a regular file at the path is an error. Stale links (directory removed from `link_crt`, or the whole `ca` block deleted) are deleted; if a regular file now occupies the path, a notice is printed and the file is left alone. Every symlink path must be unique among all paths the tool writes (see [Validation rules](#validation-rules)). See [ADR-021](./adr/021-ca-cert-links.md). |

**Mode selection:** if either `cert_file` or `key_file` is set, both must be set, and reference mode is active for that CA. Otherwise generate mode is active.

**Generate-only fields** (`name` aside): `duration`, `version`, `curve`, `encrypt`, `argon_*`, `out_crt`, `out_key`, `out_qr`. Setting any of them in reference mode is an error. `link_crt` is allowed in both modes.

**A CA is pinned to its label.** The manifest records each CA's fingerprint under its label, and certs re-sign only when their signing CA label changes. So a different CA under a recorded label is an error at reconcile and `--dry-run`, before anything is written: a referenced CA whose certificate changed, a generated CA whose cert and key are both gone (it is not silently regenerated), or a generated CA whose certificate changed. A label renamed only in case (`ca "mesh"` to `ca "Mesh"`) is refused too, on every platform. An encrypted CA key is checked against its certificate when it is decrypted to sign. To switch CAs, declare the new one under a new label; to start from scratch, delete all of `out/`, manifest included. See [ADR-027](./adr/027-ca-pinned-to-label.md).

**Deleting a `ca` block.** Its `link_crt` symlinks are deleted and its manifest record is dropped. Its certificate and key files are **not** deleted: they stay on disk and the run prints a notice that they are no longer managed.

#### Signing-CA selection

Each cert resolves to exactly one signing CA:

1. `cert.ca` if set;
2. else the CA marked `default = true`, if any;
3. else if exactly one CA is declared, that CA (no ambiguity);
4. else it is a validation error (ambiguous — name a CA or mark one default).

This mirrors Terraform's provider model: one CA is the default (here via `default = true`), the rest are aliases a cert selects with `cert.ca`, and a cert that names nothing gets the default. Per-CA `groups` / `networks` / `unsafe_networks` restrictions are validated against each cert **relative to the CA that signs it**. See [ADR-015](./adr/015-multiple-cas-per-config.md). For the rotation workflow built on this, see [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md) and the [rotation example](#ca-rotation-example) below.

#### `link_crt` example

`link_crt` is most useful paired with `cert.output_dir`. Declare the same set of directories in both fields so every per-provider directory contains both the certs and the CA cert it needs:

```hcl
ca "mesh" {
  name     = "mesh-2026"
  duration = "8760h"
  link_crt = ["out/hetzner", "out/aws"]
}

cert "lh_fra" {
  networks   = ["10.42.0.1/16"]
  output_dir = "out/hetzner"
}

cert "app_01" {
  networks   = ["10.42.1.10/16"]
  output_dir = "out/aws"
}
```

Result after `nebula-pki`:

```
out/
  ca/
    mesh.crt              ← real CA certificate
  hetzner/
    lh-fra.crt
    lh-fra.key
    mesh.crt → ../ca/mesh.crt   ← relative symlink
  aws/
    app-01.crt
    app-01.key
    mesh.crt → ../ca/mesh.crt   ← relative symlink
```

When `out_crt` renames the CA cert file, the symlink filename follows:

```hcl
ca "mesh" {
  out_crt  = "out/ca/ca.crt"            # cert written as ca.crt
  link_crt = ["out/hetzner", "out/aws"]
}
# creates: out/hetzner/ca.crt → ../../ca/ca.crt
#          out/aws/ca.crt     → ../../ca/ca.crt
```

### `trust_bundle`

Declares a CA trust bundle: a concatenated PEM of the member CA certificates, suitable for `pki.ca` in each node's `config.yaml`. It contains no key material. The block label is required (`trust_bundle "<label>" {}`) and names the bundle's file: `trust_bundle "main"` writes `main.crt`. A config may declare any number of bundles, each its own trust set; labels must be unique ignoring case. See [ADR-026](./adr/026-trust-bundle-block.md).

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ca_refs` | list(CA reference) | yes | — | The member CAs, as `ca.<label>` references, e.g. `[ca.current, ca.next]`. Non-empty, no duplicates, every reference must name a declared CA. The bundle holds the certificates in this order. |
| `path` | string | no | `<storage.out_dir>/bundles/<label>.crt` | Path for the bundle file. Relative paths resolve against the config file's directory. |
| `link_crt` | list(string) | no | `[]` | Directories where a relative symlink to the bundle is placed. The symlink filename is the basename of `path` (`<label>.crt` by default). Same semantics as `ca.link_crt`. |

**No block, no bundle.** Without a `trust_bundle` block no bundle file is written and the manifest has no `trust_bundles` record; there is no implicit bundle. Point `pki.ca` at a CA certificate directly in that case, or declare a `trust_bundle` from the start (even with a single member) when the network may ever rotate, so `pki.ca` keeps one stable path.

**Membership does not restrict signing.** A CA may be in several bundles or in none. Any declared CA may sign certs, and `default = true` only picks the signing CA for certs that omit `cert.ca`. Keeping signing in step with what nodes trust is the operator's job; during a rotation, moving `default = true` is what stops the old CA from signing.

**The label is the identity**, as for `ca` and `cert`. Renaming a label is a new bundle: it is written, and the old file stays on disk with a notice that it is no longer managed (unless the new bundle writes the same `path`). The same applies when a block is removed or its `path` changes. The bundle's old symlinks are deleted, except where a current block declares the same symlink path.

**Reference errors** (an element that is not a `ca.<label>` reference, an undeclared CA, a duplicate, an empty list, a missing `ca_refs`) carry the offending expression's source range, like `cert.ca` errors.

```hcl
trust_bundle "main" {
  ca_refs  = [ca.current]
  link_crt = ["out/hetzner", "out/aws"]
}

ca "current" {
  name = "mesh-2026"
}

cert "lh_fra" {
  networks   = ["10.42.0.1/16"]
  output_dir = "out/hetzner"
}
# creates: out/bundles/main.crt
#          out/hetzner/main.crt → ../bundles/main.crt
#          out/aws/main.crt     → ../bundles/main.crt
```

`ca.link_crt` and `trust_bundle.link_crt` may name the same directory as long as the symlink filenames differ (`current.crt` and `main.crt`). Prefer a bundle's `link_crt` for `pki.ca`: its content stays correct before, during, and after a rotation, while a single CA's symlink does not.

### `storage`

Defaults applied to every cert that does not override paths via `output` or `out_crt` / `out_key`. Also picks the encryption backend.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `out_dir` | string | no | `"out"` | Root directory for default-path artifacts. Relative paths resolve against the config file's directory. |
| `manifest_file` | string | no | `<out_dir>/nebula-pki.json` | Path for the manifest JSON. Relative paths resolve against the config file's directory; absolute paths are honoured. Override when sharing a working directory between multiple HCL configs. |
| `encryption` | block | no | `encryption "none" {}` | Encryption backend. |

The block label (`"none"`, `"sops"`, `"external"`) selects the backend. In the formal JSON Schema the label is projected as a `label` field, matching the `output` block convention.

#### `encryption "none" {}`

No fields. Private keys are written as plaintext.

#### `encryption "sops" { ... }`

Shells out to the `sops` binary. **The `sops` binary must be in PATH** when this backend is active — both for initial key generation (encrypt) and for any reconcile that signs certs under an encrypted CA key (decrypt). Every field is optional and maps 1:1 to a `sops` CLI flag. When all key-type fields are empty, sops performs its standard upward search for `.sops.yaml` from the output file's directory and applies whichever `creation_rules` match. When at least one recipient field is set, those values are passed as explicit flags to sops and take precedence over `.sops.yaml` — same behaviour as `sops --encrypt --age ... --pgp ...`.

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

When the block is left empty (`encryption "sops" {}`), nebula-pki relies entirely on `.sops.yaml`. This is the recommended setup when an operator already runs sops for other secrets. On every non-dry-run reconcile, `nebula-pki` sweeps the output directory for leftover `.nebula-pki-plain-*` temp files from any previous abnormal exit and removes them before proceeding (see ADR-003 §"Plaintext temp file during encryption").

#### `encryption "external" { ... }`

Invokes operator-supplied commands to encrypt and decrypt private key files. Both commands are required.

| Field | Type | Required | Description |
|---|---|---|---|
| `encrypt_command` | list(string) | **yes** | Argv for encryption. `{{.InPath}}` is substituted with an absolute path to a temp file containing the plaintext; if absent, plaintext is piped via stdin. `{{.OutPath}}` is substituted with the path where the command must write ciphertext; if absent, ciphertext is read from stdout. |
| `decrypt_command` | list(string) | **yes** | Argv for decryption. `{{.InPath}}` is substituted with an absolute path to a temp file containing the ciphertext; if absent, ciphertext is piped via stdin. Output is always captured from stdout (`{{.OutPath}}` is not substituted in decrypt). |
| `output_suffix` | string | no | Suffix appended to encrypted key filenames on disk. Default `".enc"`. |

**Mismatch detection:** a SHA-256 hash of the full `encrypt_command` slice is stored as `recipients_sha` in the manifest. When this changes between runs, nebula-pki prints the same mismatch warning as the sops backend and directs the operator to run `nebula-pki rekey`.

See [ADR-023](./adr/023-external-backend-protocol.md) for the full protocol and rationale.

### `cert`

Each `cert` block produces one `nebula-cert sign` invocation. The simplest form is:

```hcl
cert "app_01" {
  networks = ["10.42.1.10/16"]
}
```

The block label (`app_01` above) is the **HCL identifier**: the manifest key and the target of cross-block references. The certificate's common name defaults to the label, so most certs need nothing more.

Set the optional `name` field when the certificate CN needs characters HCL labels cannot represent (e.g. dots), or when the manifest key and the operationally-visible cert name should evolve independently. Full rationale in [ADR-009](./adr/009-cert-label-vs-cert-name.md).

| Field | Type | Required | `nebula-cert sign` flag | Description |
|---|---|---|---|---|
| _label_ | identifier | yes | — | HCL identifier; manifest key. Conventionally snake_case. |
| `name` | string | no (defaults to label) | `-name` | Certificate common name. Use when label and CN should differ. |
| `ca` | reference (`ca.<label>`) | conditional | `-ca-crt`/`-ca-key` (selects which) | Reference to the signing CA, e.g. `ca = ca.next`; a quoted string is not a reference and is rejected. `ca = null` is the same as omitting it. Optional when the file has exactly one CA or a CA is marked `default = true` (omit to use the default, or set explicitly); required when the file has more than one CA and none is marked `default`. See [ADR-015](./adr/015-multiple-cas-per-config.md) and [ADR-025](./adr/025-ca-references.md). |
| `networks` | list(CIDR) | yes | `-networks` | Overlay addresses for this cert. Each entry is a full CIDR, e.g. `"10.42.0.1/16"`. |
| `groups` | list(string) | no | `-groups` | Free-form group tags. |
| `unsafe_networks` | list(CIDR) | no | `-unsafe-networks` | Subnets this cert may route for. |
| `duration` | duration | no | `-duration` | Cert validity. Defaults to 1 second before CA expiry, matching `nebula-cert`. |
| `renew_before` | duration | no | — | Re-sign this cert when within this window of `not_after`. Falls back to the signing CA's `renew_before`, then to no time-based renewal. Must be less than the effective validity. See [ADR-017](./adr/017-cert-renewal-threshold.md). |
| `output_dir` | string | no | — | Destination directory for this cert and its key. Relative paths resolve against the config file's directory; absolute paths are honoured. When omitted, defaults to `<storage.out_dir>/certs`. See [ADR-020](./adr/020-output-dir-per-cert.md). |
| `out_crt` | string | no | `-out-crt` | Cert path component. Joined onto `output_dir` when that is set; otherwise resolved relative to the config file. May be a bare filename (`nebula.crt`) or a relative sub-path (`certs/nebula.crt`). Defaults to `<cert.name>.crt` within the base directory. |
| `out_key` | string | no | `-out-key` | Key path component. Same joining semantics as `out_crt`. Forbidden together with `in_pub` (no key is written). Defaults to `<cert.name>.key` within the base directory. |
| `out_qr` | string | no | `-out-qr` | Path for the optional QR PNG, joined onto `output_dir` when set. QR contents are public; encryption is never applied. |
| `in_pub` | string | no | `-in-pub` | Path to a PEM **public key** exported by the device. When set, the CLI signs that public key and writes **only** the cert — no private key is generated or written, and no encryption applies. The key's curve must match the signing CA. Enables the "private key never leaves the device" pattern (mobile, HSM, separation of duties). Mutually exclusive with `out_key`. Mirrors `nebula-cert sign -in-pub`. See [ADR-018](./adr/018-in-pub-air-gapped-signing.md). |

#### Path resolution

For each cert, the base directory and file paths are resolved as follows:

```
base      = output_dir              if set
            else <storage.out_dir>/certs

cert_path = Join(base, out_crt)     if out_crt set
            else Join(base, <cert.name>.crt)

key_path  = Join(base, out_key)     if out_key set
            else Join(base, <cert.name>.key)

qr_path   = Join(base, out_qr)     if out_qr set  (cert only; no encryption)
```

`filepath.Join` concatenates and cleans. A bare filename in `out_crt` / `out_key` stays in `base`; a relative sub-path (`certs/node.crt`) nests inside it. When an absolute final path is needed, make `output_dir` absolute and use bare filenames in `out_crt` / `out_key` — combining an absolute `out_crt` with a set `output_dir` produces a joined result, not an override.

Encryption suffix is appended only to the **key** file (`.key` → `.key<suffix>`), and only when the active encryption backend is not `none`. Cert (`.crt`) and QR (`.png`) files are never encrypted and never suffixed.

When `in_pub` is set, no `.key` is written — only the `.crt` (and `.png`, if `out_qr`). The encryption suffix logic does not apply. See [ADR-018](./adr/018-in-pub-air-gapped-signing.md).

## Paths

Relative paths resolve against the config file's directory; absolute paths are used as written.

**One spelling per path.** Every configured path is cleaned (`filepath.Clean`) when the config is loaded: `./out/b.crt`, `out//b.crt` and `out/x/../b.crt` all become `out/b.crt`, and a trailing separator on a directory is dropped. Everything downstream (planning, writing, symlink targets, messages, the manifest) sees that one spelling, so changing how a path is written without changing the file it names changes nothing. Paths a manifest already records are compared with configured ones by the file they name (resolved against the config directory, then cleaned), never as strings. See [ADR-026](./adr/026-trust-bundle-block.md) "Detailed rules".

**File fields name a file.** `trust_bundle.path`, `storage.manifest_file`, `ca.out_crt` / `out_key` / `out_qr` / `cert_file` / `key_file` and `cert.out_crt` / `out_key` / `out_qr` / `in_pub` must not end in a separator or in `.` / `..`. Directory fields (`storage.out_dir`, `cert.output_dir`, every `link_crt` entry) may end in a separator.

**Uniqueness ignores case.** Labels within one block group, cert names, and every path the tool writes must be unique ignoring case, because macOS and Windows filesystems treat `main.crt` and `Main.crt` as one file. The rule applies on every platform, so `check` gives the same answer everywhere.

## Complete example

```hcl
trust_bundle "main" {
  ca_refs  = [ca.wiech-mesh]
  link_crt = ["out/hetzner", "out/aws"]
}

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

cert "lh_fra" {
  name       = "lh-fra"
  networks   = ["10.42.0.1/16"]
  groups     = ["lighthouse"]
  output_dir = "out/hetzner"
}

cert "app_01" {
  networks   = ["10.42.1.10/16"]
  groups     = ["app"]
  output_dir = "out/hetzner"
}

cert "app_02" {
  networks   = ["10.42.1.11/16"]
  groups     = ["app"]
  output_dir = "out/aws"
}

cert "router_edge" {
  name            = "router-edge"
  networks        = ["10.42.2.1/16"]
  unsafe_networks = ["192.168.10.0/24"]
  groups          = ["router"]
  # Falls back to default path under storage.out_dir/certs/
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

cert "new_app" {
  networks = ["10.42.3.1/16"]
  groups   = ["app"]
}
```

A referenced CA is pinned to its label by the fingerprint the manifest records. Moving the same CA to another path is fine. A different CA behind `cert_file` under the same label (a new CA at the same path, the wrong branch or environment) fails the run before anything is written; to switch, declare the new CA under a new label. See [ADR-027](./adr/027-ca-pinned-to-label.md).

## CA rotation example

A worked rotation across a CA expiry, using two labelled CAs in one file. Each stage is a small edit to the same `nebula.hcl` followed by `nebula-pki`. The tool emits the artifacts; the operator distributes them and reloads certs (the tool never pushes — see [ADR-016](./adr/016-ca-rotation-and-trust-bundles.md)). Every trust change is an edit to `trust_bundle.ca_refs`; see [ADR-026](./adr/026-trust-bundle-block.md).

**Stage 0 — steady state, one CA.** Declare the `trust_bundle` from the start so `pki.ca` keeps one stable path through the whole rotation.

```hcl
trust_bundle "main" {
  ca_refs = [ca.current]
}

ca "current" {
  name     = "mesh-2026"
  duration = "8760h"
  networks = ["10.42.0.0/16"]
}

cert "app_01" { networks = ["10.42.1.10/16"] }   # only one CA, no cert.ca needed
```

`out/bundles/main.crt` contains just `current`.

**Stage 1 — add the new CA and trust it.** Add `ca "next"` and list it in `ca_refs`. The bundle now carries both; ship `main.crt` to every node and reload (nodes now *trust* both CAs; certs still signed by `current`). Mark `current` as the default so existing certs keep being signed by it without per-cert edits.

```hcl
trust_bundle "main" {
  ca_refs = [ca.current, ca.next]
}

ca "current" {
  name     = "mesh-2026"
  duration = "8760h"
  networks = ["10.42.0.0/16"]
  default  = true                 # certs without `ca` are signed by current
}

ca "next" {
  name     = "mesh-2027"
  duration = "8760h"
  networks = ["10.42.0.0/16"]     # same restrictions
}

cert "app_01" { networks = ["10.42.1.10/16"] }
```

**Stage 2 — flip the signing CA.** Move the `default = true` marker from `current` to `next`. On the next run every defaulted cert is re-signed under `next`; distribute the new certs and reload. (Canary first by setting `ca = ca.next` on a few certs before moving the default.)

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

**Stage 3 — stop trusting the old CA.** Remove `current` from `ca_refs`; ship the slimmer `main.crt` and reload. `current` keeps its manifest record. Nothing stops it from signing, but after stage 2 no cert uses it: keep it that way, since nodes no longer trust it.

```hcl
trust_bundle "main" {
  ca_refs = [ca.next]
}
```

**Stage 4 — retire the old CA.** Delete the `ca "current"` block once satisfied. Its manifest record is dropped and its symlinks are deleted; its cert and key files stay on disk with a notice, for you to remove. A forgotten `ca.current` reference anywhere fails the parse.

## Air-gapped (`in_pub`) example

For certs whose private key must never leave the device — mobile, HSM-backed, or separation-of-duties. The device generates its own keypair (`nebula-cert keygen` on the device, or the Mobile Nebula app) and exports only the public key. The operator drops that `.pub` where the config points; `nebula-pki` signs it and writes a cert only. See [ADR-018](./adr/018-in-pub-air-gapped-signing.md).

```hcl
ca "mesh-2026" {
  name     = "mesh-2026"
  duration = "8760h"
}

cert "alice_phone" {
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

cert "app_01" { networks = ["10.99.0.10/16"] }
```

`prod.hcl`:

```hcl
ca "prod" { name = "prod-mesh" }

storage {
  out_dir       = "out/prod"
  manifest_file = "out/prod.nebula-pki.json"
}

cert "app_01" { networks = ["10.42.0.10/16"] }
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
  bundles/
    main.crt
  hetzner/
    lh-fra.crt
    lh-fra.key.enc
    app_01.crt
    app_01.key.enc
    main.crt → ../bundles/main.crt
  aws/
    app_02.crt
    app_02.key.enc
    main.crt → ../bundles/main.crt
  certs/
    router-edge.crt
    router-edge.key.enc
```

## CLI reference

### Default action

```sh
nebula-pki                # reconcile out/ with nebula.hcl
nebula-pki --dry-run      # preview planned writes; no files modified
nebula-pki check          # validate config only; no I/O against out/
nebula-pki -c <path>      # use a different config (default: ./nebula.hcl)
```

### `nebula-pki rekey`

Synchronizes the encryption of all managed private key files with the current storage backend config.

> **Note:** `rekey` operates on private key files at rest (the storage encryption configured in the `storage { encryption ... }` block). It has nothing to do with Nebula network certificates or tunnel encryption.

```sh
nebula-pki rekey            # process all files with a detectable mismatch
nebula-pki rekey --dry-run  # print what would change; no writes
nebula-pki rekey --force    # process all managed key files regardless of mismatch
```

`rekey` handles three cases in a single pass:

| Transition | Trigger |
|---|---|
| Plaintext → encrypted | Storage encryption added to config since last run |
| Encrypted → re-encrypted | Recipients or backend changed |
| Encrypted → plaintext | Encryption block removed from config (or set to `encryption "none" {}`) |

Without `--force`, only files with a detectable mismatch are processed:

- For sops with inline recipients: stored `recipients_sha` differs from current hash.
- For sops with `.sops.yaml`-only mode (empty block): no hash is stored, so no mismatch can be detected. Use `--force` after rotating `.sops.yaml` keys.
- For external: SHA-256 of stored `encrypt_command` differs from current hash.
- For path mismatch (suffix changed): the manifest-recorded key path differs from the path the current config expects.

The manifest is updated only when all files succeed. On partial failure the manifest is left unchanged; re-running `rekey` is safe — already-matching files are skipped.

See [ADR-008](./adr/008-cli-surface.md) for the rationale for `rekey` being a subcommand.

## Validation rules

CA and multi-CA:

- A configuration file declares zero `ca` blocks.
- A `ca` block has no label (unlabelled `ca {}` is a parse error; use `ca "<label>" {}`).
- Two `ca` blocks share a label, ignoring case (`mesh` and `Mesh` clash).
- A `ca` label is not a valid identifier (`^[A-Za-z_][A-Za-z0-9_-]*$`).
- More than one `ca` block sets `default = true`.
- `cert.ca` is not a reference of the form `ca.<label>` (a quoted string, the index form `ca["<label>"]`, a bare `ca`, extra steps, or another root such as `cert.x`).
- `cert.ca` references a CA label that is not declared.
- A cert's signing CA is ambiguous: the file has >1 CA, the cert has no `cert.ca`, and no CA is marked `default = true`.
- `ca` is in reference mode but only one of `cert_file` / `key_file` is set.
- `ca` is in reference mode and sets generate-only fields (`name`, `duration`, `curve`, `version`, `out_*`, `argon_*`, `encrypt`).
- At reconcile and `--dry-run` (not `check`, which does not read the manifest): a CA's certificate fingerprint differs from the one the manifest records under its label, or a generate-mode CA the manifest records has neither its cert nor its key on disk, or a CA label the manifest does not record differs only in case from a removed label it does record ([ADR-027](./adr/027-ca-pinned-to-label.md)).
- When a cert is signed: an encrypted CA key does not belong to its certificate.

Trust bundle:

- Two `trust_bundle` blocks share a label, ignoring case.
- A `trust_bundle` label is not a valid identifier (`^[A-Za-z_][A-Za-z0-9_-]*$`).
- `trust_bundle.ca_refs` is missing, empty, or not a list.
- A `ca_refs` element is not a reference of the form `ca.<label>`, references an undeclared CA, or repeats a member.

Paths and symlinks:

- A field that names a file ends in a separator or in `.` / `..` (see [Paths](#paths)).
- A `link_crt` entry (on a `ca` or a `trust_bundle`) is empty or repeats a directory of the same list (after cleaning, ignoring case).
- Two things write the same path. Every path the tool writes must be unique: CA certificates and keys (with the encryption suffix), cert certificates and keys, bundle files, `link_crt` symlinks, and the manifest. No write may target a referenced CA's `cert_file` or `key_file` (reference CAs may share those inputs). Paths are compared after resolving, cleaning and ignoring case, so `out/x/`, `out/x` and `out/X` are the same. The error names every owner, e.g. `path out/s/main.crt is used by ca "a" (link_crt), ca "b" (link_crt) and trust_bundle "main" (link_crt)`. This also catches a symlink that would replace its own target, such as `link_crt` naming the bundle's own directory.
- A written file is also a directory holding another path, e.g. a bundle `path = "out/certs"` while certs are written to `out/certs/`. The error names the owners of both paths.

Certs:

- Two `cert` blocks share a label, ignoring case.
- Two `cert` blocks (after `name` defaulting) share a certificate `name`, ignoring case.
- Two `cert` blocks share an overlay address (the `Addr()` of the first prefix in `networks`, regardless of prefix length). `nebula-cert` cannot detect cross-cert conflicts; catching them at config time avoids deploying a broken Nebula network.
- A `cert.networks` entry is not a valid CIDR.
- A `cert.duration` exceeds its signing CA's `not_after`.
- A `cert` sets both `in_pub` and `out_key` (no key is written when signing a supplied public key).
- A `cert.in_pub` file's public-key curve does not match its signing CA's curve (checked at reconcile/`check`, not parse time — the file must be read).
- `cert.groups` references a group not permitted by its signing CA's `groups` (when that CA's `groups` is non-empty).
- `cert.networks` contains a prefix not contained by any of its signing CA's `networks` prefixes (when that CA's `networks` is non-empty).
- `cert.unsafe_networks` contains a prefix not contained by any of its signing CA's `unsafe_networks` prefixes (when that CA's `unsafe_networks` is non-empty).

Renewal:

- A cert's effective `renew_before` (from `cert.renew_before` or the signing CA's `renew_before`) is greater than or equal to the cert's effective validity (`duration`, or CA-expiry-minus-1s when unset). See [ADR-017](./adr/017-cert-renewal-threshold.md).

Groups and storage:

- Any `groups` entry (on `ca` or `cert`) is empty, contains a comma, or contains leading/trailing whitespace. Group strings are otherwise free-form UTF-8; commas are forbidden because `nebula-cert`'s flag is comma-separated.
- Multiple `encryption` blocks in a single `storage`.

## References between blocks

The schema has one kind of cross-block reference, `ca.<label>`, used in two places: a cert names its signing CA with `cert.ca = ca.<label>` (with the CA marked `default = true` as the fallback when `cert.ca` is omitted), and the trust bundle lists its members with `trust_bundle.ca_refs = [ca.<label>, …]`. A reference is an HCL traversal read as syntax, never evaluated: the schema does not use `hcl.EvalContext`, so `ca.next` cannot leak into string interpolation. Only the attribute form is accepted, and every reference error carries the expression's source range. See [ADR-025](./adr/025-ca-references.md), [ADR-026](./adr/026-trust-bundle-block.md) and [ADR-005](./adr/005-hcl-schema-decision.md).

Certs name their destination directory via `output_dir`. See [ADR-020](./adr/020-output-dir-per-cert.md) for the rationale, path-resolution rules, and the conditions under which multi-directory fan-out would be reintroduced.

If a future field needs to reference another block (per-output encryption recipients, for example), it will be added by reintroducing a named `output` block alongside the inline form, following the same `<block>.<label>` reference pattern as `cert.ca`.

## Labels vs. names (worked example)

```hcl
cert "app_prod_01" {              # label only; cert CN = "app_prod_01"
  networks = ["10.42.1.10/16"]
}

cert "app_prod_02" {
  name     = "app-prod-02.mesh"   # cert CN differs from label
  networks = ["10.42.1.11/16"]
}
```

The label is the manifest key and the reference target. The `name` is what ends up inside the cert and what appears in Nebula's logs. Rationale in [ADR-009](./adr/009-cert-label-vs-cert-name.md).

## Schema evolution

The HCL has no version field today. If a breaking change becomes necessary, a forward-compatible mechanism is introduced at that point: a top-level `nebula_pki { schema = 2 }` block. Configs without it default to `schema = 1`. This avoids forcing an explicit version on day-one users while leaving a clear migration door open. The manifest already carries an explicit `schema_version`; see [`adr/002-state-and-artifact-layout.md`](./adr/002-state-and-artifact-layout.md) and [`adr/007-schema-evolution.md`](./adr/007-schema-evolution.md).
