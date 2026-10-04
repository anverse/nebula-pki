# nebula-pki — operator & agent reference

Companion to [`readme.md`](./readme.md). This file holds operational detail, full option tables, file layout, schema-stability policy, and pointers into the spec. Agents and operators reading this should treat [`spec/`](./spec/readme.md) as the authoritative source.

## Scope recap

- Wraps `nebula-cert` (slackhq/nebula).
- HCL fields mirror `nebula-cert ca` and `nebula-cert sign` flags 1:1 with underscores.
- Adds: declarative config, per-cert `output_dir` for custom certificate placement, optional at-rest encryption of private keys (`sops` or any external command), a JSON manifest.
- One or more labelled `ca "<label>" {}` blocks per HCL file, for rotation and multi-CA Nebula networks ([ADR-015](./spec/adr/015-multiple-cas-per-config.md), supersedes [ADR-010](./spec/adr/010-single-ca-per-config.md)). Isolated environments may still use one file each.
- Emits a CA trust bundle for `pki.ca` for each declared `trust_bundle` block ([ADR-026](./spec/adr/026-trust-bundle-block.md)) and supports declarative CA rotation ([ADR-016](./spec/adr/016-ca-rotation-and-trust-bundles.md)), time-based renewal via `renew_before` ([ADR-017](./spec/adr/017-cert-renewal-threshold.md)), and air-gapped `in_pub` signing ([ADR-018](./spec/adr/018-in-pub-air-gapped-signing.md)).
- Does not render `config.yaml`, does not push files (including during rotation), does not implement lighthouse/blocklist/firewall.

> Capability detail for the four areas above (multi-CA, rotation/bundle, `renew_before`, `in_pub`) is also covered in [`spec/`](./spec/readme.md) and the cited ADRs. Where anything conflicts, `spec/hcl-schema.md` is the final authority.

## CLI

```sh
nebula-pki                    # reconcile out/ with nebula.hcl
nebula-pki --dry-run          # preview only; write nothing
nebula-pki --no-renewal       # skip time-based renewal; other re-sign triggers still apply
nebula-pki check              # parse + validate config; no I/O against out/. Reads referenced CA files and in_pub keys.
nebula-pki rekey              # re-encrypt managed private keys with the current encryption config
nebula-pki rekey --dry-run    # preview rekey; write nothing
nebula-pki rekey --force      # re-encrypt every managed key, mismatch or not
nebula-pki --version          # print version (also: nebula-pki version)
nebula-pki -c <path>          # alternate config path (default: ./nebula.hcl)
```

Exit codes: `0` on success or clean dry-run; `1` on validation/runtime error; `2` on usage error.

After each reconcile and `--dry-run` (including no-op runs), the tool prints to stderr the earliest actionable deadline — the soonest of a cert entering its `renew_before` window or the expiry of any cert without a threshold — plus a "run again before `<date>`" hint. Advisory only; it changes no exit code and triggers no writes. See [`spec/adr/017-cert-renewal-threshold.md`](./spec/adr/017-cert-renewal-threshold.md).

Deferred:

- `nebula-pki show` — human summary of `out/nebula-pki.json`. Operators can `jq` the manifest until this lands. See [`spec/adr/008-cli-surface.md`](./spec/adr/008-cli-surface.md).

## Labels vs. cert names

By default, the block label is everything: manifest key, reference target, and cert common name.

```hcl
cert "app_prod_01" {
  networks = ["10.42.1.10/16"]
}
# cert CN = "app_prod_01"; manifest key = "app_prod_01"
```

Set the optional `name` field only when label and CN should differ (cert needs characters HCL labels can't carry, or you want to evolve the two independently):

```hcl
cert "edge_router" {
  name     = "edge-router.mesh"
  networks = ["10.42.2.1/16"]
}
# cert CN = "edge-router.mesh"; manifest key = "edge_router"
```

Default file paths use the **cert name**, not the label. Full rationale in [`spec/adr/009-cert-label-vs-cert-name.md`](./spec/adr/009-cert-label-vs-cert-name.md).

## References between blocks

The only cross-block reference is the CA reference `ca.<label>`. It appears as `cert.ca = ca.<label>` (with the CA marked `default = true` as the fallback when omitted), selecting the signing CA when more than one CA exists ([ADR-015](./spec/adr/015-multiple-cas-per-config.md), [ADR-025](./spec/adr/025-ca-references.md)), and as the elements of `trust_bundle.ca_refs` ([ADR-026](./spec/adr/026-trust-bundle-block.md)). A reference is an HCL traversal read as syntax, never evaluated, so the schema needs no `hcl.EvalContext`. Only the attribute form is accepted (`ca["x"]` and quoted strings are rejected), and reference errors carry the expression's source range. Certs name their destination directory directly via `cert.output_dir`. See [ADR-005](./spec/adr/005-hcl-schema-decision.md) and [ADR-020](./spec/adr/020-output-dir-per-cert.md).

## Using an existing CA (reference mode)

```hcl
ca "shared-root" {
  cert_file = "/path/to/ca.crt"
  key_file  = "/path/to/ca.key"
}
```

In reference mode, generate-only fields (`name`, `duration`, `curve`, `version`, `encrypt`, `argon_*`, `out_*`) are rejected. The tool only reads the CA files; it never rewrites them.

On a run, nebula-pki loads the referenced pair and verifies it before recording anything: the certificate must be a CA (`IsCA`), its self-signature must verify, the key's curve must match the certificate, and the key must correspond to the certificate's public key. A missing `cert_file`/`key_file` is a hard error. An **expired** referenced CA is recorded anyway with a warning on stderr; the operator owns the CA in reference mode. The manifest records `cas.<label>.mode = "reference"` with the CA's fingerprint, validity window, and the referenced paths; `out/ca/` is never written. `nebula-pki check` additionally reads the referenced files and prints the CA fingerprint.

Reference-mode reconcile is idempotent: a second run against an unchanged referenced CA writes nothing (the manifest stays byte-identical). Pointing `cert_file`/`key_file` at a different CA updates the manifest's recorded fingerprint on the next run.

## Full CA options (generate mode)

```hcl
ca "label" {
  # Identity
  name              = "wiech-mesh"
  default           = true                   # default signing CA for certs that omit cert.ca

  # Validity
  duration          = "26280h"               # 3 years
  renew_before      = "720h"                 # re-sign certs 30 days before expiry (inherited)

  # Certificate format
  version           = 2                      # cert format 1 or 2
  curve             = "25519"                # or "P256"

  # Subordinate cert restrictions (validated per cert)
  groups            = ["lighthouse", "app"]
  networks          = ["10.42.0.0/16"]
  unsafe_networks   = ["192.168.0.0/16"]

  # Passphrase-encrypted CA key (nebula-cert -encrypt): parsed, but
  # encrypt = true is rejected at runtime. Use storage.encryption instead.
  encrypt           = false
  argon_memory      = 2097152
  argon_iterations  = 1
  argon_parallelism = 4

  # Output path overrides
  out_crt           = "out/ca/ca.crt"
  out_key           = "out/ca/ca.key"
  out_qr            = "out/ca/ca.png"           # parsed; no QR file is written yet

  # Relative symlinks to this CA's cert, one per directory (ADR-021)
  link_crt          = ["out/hetzner", "out/aws"]
}
```

## Trust bundles

```hcl
trust_bundle "main" {
  ca_refs  = [ca.current, ca.next]        # required; members in bundle order
  path     = "out/bundles/main.crt"       # default <storage.out_dir>/bundles/<label>.crt
  link_crt = ["out/hetzner", "out/aws"]   # relative main.crt symlinks (basename of path)
}
```

- Any number of `trust_bundle` blocks, labels unique. Without any, no bundle is written and the manifest has no `trust_bundles` record; there is no implicit bundle.
- Bundles describe trust only. A CA may be in several bundles or none, and any declared CA may sign; `default = true` only picks the signing CA for certs that omit `cert.ca`.
- Rotation: add the new CA to `ca_refs`, move `default = true`, drop the old CA from `ca_refs`, then delete its `ca` block.
- The label is the identity and the default file name (`trust_bundle "main"` → `out/bundles/main.crt`, symlinks `main.crt`). Renaming the label, removing the block or changing `path` writes the new bundle and leaves the old file on disk with a notice; old symlinks are deleted unless a current block declares the same path.
- Deleting a `ca` block deletes its `link_crt` symlinks and drops its manifest record; a generate-mode CA's cert and key files stay on disk with a notice, a reference-mode CA's files were never managed (no notice).

## Full cert options

```hcl
cert "router" {
  name            = "router.mesh"               # optional; defaults to label
  ca              = ca.my-ca                    # signing CA reference; omit to use the default CA
  networks        = ["10.42.2.1/16", "fd42::1/64"]
  unsafe_networks = ["192.168.10.0/24"]
  groups          = ["router"]
  duration        = "8760h"
  renew_before    = "48h"                       # overrides CA-level renew_before for this cert
  output_dir      = "out/routers"               # destination directory; defaults to out/certs
  in_pub          = "./pre-generated/router.pub"
  out_crt         = "out/router.crt"
  out_key         = "out/router.key"
  out_qr          = "out/router.png"           # parsed; no QR file is written yet
}
```

Path resolution for a cert and its key (see [ADR-020](./spec/adr/020-output-dir-per-cert.md)):

```
base      = output_dir              if set
          = <storage.out_dir>/certs  otherwise
cert_path = Join(base, out_crt)     if out_crt set
          = Join(base, <name>.crt)  otherwise
key_path  = Join(base, out_key)     if out_key set
          = Join(base, <name>.key)  otherwise
```

`out_crt` and `out_key` compose with `output_dir` rather than overriding it; a bare filename stays in `base`, a relative sub-path nests inside it.

## Encryption backends

Only private key files are encrypted; certificates, the trust bundle, and the manifest stay plaintext. Encrypted keys get `output_suffix` appended (default `.enc`). When the configured recipients (sops) or `encrypt_command` (external) change, every run warns until `nebula-pki rekey` re-encrypts the existing keys. Full reference in [`spec/hcl-schema.md`](./spec/hcl-schema.md); rationale in [ADR-003](./spec/adr/003-encryption-strategy.md).

### `none` (default)

```hcl
storage { encryption "none" {} }   # equivalent to omitting the block
```

### `sops`

Shells out to the `sops` binary, which must be in `PATH` whenever this backend is active (encrypting new keys and decrypting an encrypted CA key to sign). Every field is optional and maps 1:1 to a sops CLI flag (`age`→`--age`, `pgp`→`--pgp`, `kms`→`--kms`, `gcp_kms`→`--gcp-kms`, `azure_kv`→`--azure-kv`, `hc_vault_transit`→`--hc-vault-transit`, `shamir_threshold`→`--shamir-secret-sharing-threshold`, `config`→`--config`). When all key-type fields are empty, the sops library performs its standard upward search for `.sops.yaml` and applies whichever `creation_rules` match the output path.

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

Decrypt manually with the regular `sops` CLI, which resolves the same `.sops.yaml` rules.

### `external` (any command)

```hcl
storage {
  encryption "external" {
    encrypt_command = ["age", "-e", "-r", "age1abc...", "-o", "{{.OutPath}}", "{{.InPath}}"]
    decrypt_command = ["age", "-d", "-i", "age.key", "{{.InPath}}"]
    output_suffix   = ".age"
  }
}
```

Both commands are required. `{{.InPath}}` is replaced by a temp file holding the input (plaintext for encrypt, ciphertext for decrypt); without it, the input is piped via stdin. In `encrypt_command`, `{{.OutPath}}` is where the command must write ciphertext; without it, ciphertext is read from stdout. Decrypt output is always read from stdout. See [ADR-023](./spec/adr/023-external-backend-protocol.md).

## Custom output directory (`output_dir`)

```hcl
cert "lh_fra" {
  networks   = ["10.42.0.1/16"]
  groups     = ["lighthouse"]
  output_dir = "out/hetzner"
}
```

`output_dir` is a single **directory**. Filenames default to `<cert.name>.crt` / `.key`; override with `out_crt` / `out_key` (path components joined onto the directory). When omitted, files land in `<storage.out_dir>/certs`. See [ADR-020](./spec/adr/020-output-dir-per-cert.md).

## Output layout

```
out/                    # storage.out_dir; safe to commit when encryption is on
  nebula-pki.json       # manifest; rename via storage.manifest_file
  ca/
    <label>.crt
    <label>.key         # <label>.key.enc when encryption is on
  bundles/
    <label>.crt         # one per trust_bundle block; path via trust_bundle.path
  certs/                # default location for certs without an `output_dir`
<custom-dir>/           # any directory set via cert.output_dir
```

The specification lives in [`spec/`](./spec/readme.md): `hcl-schema.md`, `hcl-schema.formal.json`, and the architecture decisions under [`spec/adr/`](./spec/adr/).

## Manifest

`out/nebula-pki.json` is the single source of truth across runs. Schema highlights:

- `schema_version` — integer, currently `1`.
- `generated_at`, `generator`, `config_path` — provenance of the run.
- `trust_bundles` — map keyed by bundle label, one entry per declared `trust_bundle` block: path, the fingerprints of its member CAs in `ca_refs` order, and its `links`. Absent when no bundle is declared.
- `cas` — map keyed by CA label; each record carries `mode` (`"generate"` or `"reference"`), name, fingerprint, curve, version, validity, paths, `default`, and, when set, `links` and an `encryption` record.
- `certs` — map keyed by cert label; each record carries cert name, signing CA, fingerprint, validity, the literal HCL `duration`, groups, networks, and exactly one `artifacts` entry with `cert_path`, `key_path` (absent for `in_pub` certs), and an `encryption` record when the key is encrypted.

Encryption records hold only public backend details (backend name, recipients hash, suffix), never secret material.

Full schema in [`spec/adr/002-state-and-artifact-layout.md`](./spec/adr/002-state-and-artifact-layout.md).

## Schema stability policy

The HCL has **no version field today**. If a breaking change becomes necessary later:

- An optional top-level `nebula_pki { schema = 2 }` block will be introduced.
- Configs without it continue to parse as `schema = 1`.

The manifest already carries an explicit `schema_version` field from day one — downstream tooling parsing the manifest needs an unambiguous signal. See [`spec/adr/007-schema-evolution.md`](./spec/adr/007-schema-evolution.md).

## Validation rules (selected)

- Duplicate `cert` labels → error.
- Duplicate cert `name`s (after defaulting from labels) → error.
- Duplicate first-prefix overlay addresses across certs → error.
- `ca` in reference mode with generate-only fields → error.
- `ca` reference mode with only one of `cert_file`/`key_file` → error.
- `ca` reference mode whose `cert_file`/`key_file` do not exist on disk → error (at reconcile/`check`, not parse time).
- `ca` reference mode whose files are not a coherent CA pair (not a CA, bad self-signature, curve/key mismatch) → error.
- Two `trust_bundle` blocks share a label → error.
- `trust_bundle.ca_refs` empty, not a list of `ca.<label>` references, naming an undeclared CA, or repeating a member → error with source range.
- Two things write the same path (CA cert/key, cert cert/key, bundle file, `link_crt` symlink, manifest), or a write targets a referenced CA's `cert_file`/`key_file` → error naming every owner.
- A written file is also the directory of another written path (e.g. bundle `path = "out/certs"`) → error naming both owners.
- More than one `ca` block sets `default = true` → error.
- `cert.ca` is not a `ca.<label>` reference → error.
- `cert.ca` references a CA that is not declared → error.
- `cert.groups` containing a group not in `ca.groups` (when restricted) → error.
- `cert.networks` containing a prefix not contained by `ca.networks` (when restricted) → error.
- `cert.unsafe_networks` containing a prefix not contained by `ca.unsafe_networks` (when restricted) → error.
- A CA's `renew_before` is ≥ its `duration` → error.
- A cert's effective `renew_before` is ≥ its effective validity → error.

Full list in [`spec/hcl-schema.md`](./spec/hcl-schema.md#validation-rules).

## Further reading

- [`spec/readme.md`](./spec/readme.md) — authoritative project spec.
- [`spec/hcl-schema.md`](./spec/hcl-schema.md) — annotated HCL reference.
- [`spec/hcl-schema.formal.json`](./spec/hcl-schema.formal.json) — JSON Schema (2020-12).
- [`spec/adr/`](./spec/adr/) — architecture decisions.
- Upstream Nebula: <https://github.com/slackhq/nebula>.
