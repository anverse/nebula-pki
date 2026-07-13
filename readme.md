# nebula-pki

`nebula-pki` is a declarative layer over [`nebula-cert`](https://github.com/slackhq/nebula).
Describe the Nebula network in one config; automatically generate and sign the certificates.

Without it, managing a Nebula network means running `nebula-cert` commands by hand: per-host flags, signing sessions in shell history, no record of what changed or when.

`nebula-pki` replaces that with an HCL config that describes every CA and host in one place.
After every run it writes `nebula-pki.json` with CA fingerprints, host cert windows, and signing CA labels.
Changes flow through pull requests with a complete, readable diff.

> nebula-pki is under active development. It's ready to use day-to-day, but breaking changes may still happen before v1.0.

## Install

### Homebrew

```sh
brew tap anverse/nebula-pki https://github.com/anverse/nebula-pki.git
brew install anverse/nebula-pki/nebula-pki
```

### Nix

Flake-based:

```sh
nix profile install github:anverse/nebula-pki
```

Or one-shot:

```sh
nix run github:anverse/nebula-pki
```

### Go

```sh
go install github.com/anverse/nebula-pki/cmd/nebula-pki@latest
```

### From source

```sh
git clone https://github.com/anverse/nebula-pki
cd nebula-pki
go build -o nebula-pki ./cmd/nebula-pki
```

The binary is self-contained.
It links the `slackhq/nebula/cert` Go library directly.
You don't need Nebula or `nebula-cert` installed alongside it.
Each release pins one upstream Nebula version.

## Getting Started

`nebula.hcl`:

```hcl
ca "my_mesh" {
  name     = "my-mesh"
  networks = ["10.42.0.0/16"]
  duration = "8760h" # 365 days
}

host "lh_01" {
  networks = ["10.42.0.1/16"]
  groups   = ["lighthouse"]
}

host "node_01" {
  networks = ["10.42.1.10/16"]
  groups   = ["node"]
}
```

```sh
nebula-pki
```

Running the tool reconciles `out/` with `nebula.hcl`.
It generates the CA if it doesn't exist, signs missing host certs, and updates the manifest at `out/nebula-pki.json`.

## Per-host output directory

Running a Nebula network that spans several Terraform projects, providers, or deploy targets? Each one usually only needs the certs for the hosts it owns. `output_dir` places a host's cert and key in a specific directory so every downstream project reads from its own folder and sees nothing else.

```hcl
host "lh_fra" {
  name       = "lh-fra"                 # cert CN; optional, defaults to label
  networks   = ["10.42.0.1/16"]
  output_dir = "out/third/party/vendor" # cert written to out/third/party/vendor/lh-fra.{crt,key}
}

host "vendor_node_01" {
  networks   = ["10.42.1.10/16"]
  output_dir = "out/vendor"
}
```

Filenames default to `<host.name>.crt` / `.key`. Use `out_crt` / `out_key` to rename them while keeping the same `output_dir`:

```hcl
host "lh_fra" {
  networks   = ["10.42.0.1/16"]
  output_dir = "out/vendor"
  out_crt    = "nebula.crt"      # → out/vendor/nebula.crt
}
```

## CA cert links

When hosts are fanned out to per-provider directories via `output_dir`, each directory also needs the CA certificate for that host to authenticate against. The CA cert lives under `out/ca/` — it doesn't follow `output_dir` automatically.

Use `link_crt` on a `ca` block to place a relative symlink of the CA certificate into each directory that needs it:

```hcl
ca "mesh" {
  name     = "mesh-2026"
  duration = "8760h"
  link_crt = ["out/hetzner", "out/aws"]
}

host "lh_fra" {
  networks   = ["10.42.0.1/16"]
  output_dir = "out/hetzner"
}

host "app_01" {
  networks   = ["10.42.1.10/16"]
  output_dir = "out/aws"
}
```

After `nebula-pki`, each output directory contains both the host's cert/key pair and a symlink to the CA cert:

```
out/
  ca/mesh.crt           ← actual CA certificate
  hetzner/
    lh-fra.crt
    lh-fra.key
    mesh.crt → ../ca/mesh.crt   ← symlink
  aws/
    app-01.crt
    app-01.key
    mesh.crt → ../ca/mesh.crt   ← symlink
```

**Symlink name** is the CA cert filename: `<label>.crt` by default, or the basename of `out_crt` when that is set. This is the same name across the CA cert file and all its links.

**Relative targets** — symlink targets are always relative (computed via `filepath.Rel`), so they survive `git clone` to any absolute path on any machine. The link `out/hetzner/mesh.crt` stores `../ca/mesh.crt` as its target, not an absolute path.

**Idempotency** — a re-run is a no-op when the symlink already points to the correct target. A broken or wrong-target symlink is recreated. A regular file at a declared link path is an error (never clobbered).

**Stale cleanup** — removing a directory from `link_crt` causes the old symlink to be deleted on the next run. If a regular file now occupies the path, a notice is printed and the file is left alone.

The manifest records each managed link under `cas.<label>.links` so the tool can detect stale links across runs.

## Trust bundle

Every run writes `out/ca/bundle.crt`, a concatenated PEM of all active CA certificates suitable for `pki.ca` in each host's Nebula `config.yaml`. The path is configurable:

```hcl
storage {
  trust_bundle_file = "out/ca/bundle.crt"   # default
}
```

With a single CA, the bundle equals that CA's certificate. During rotation it holds both the old and new CA so hosts can authenticate against either; once the old CA is archived the bundle shrinks back to the active CA only.

## CA rotation

Rotating a CA is four edits to `nebula.hcl`, each followed by a rerun:

1. **Add the new CA.** The bundle now contains both; distribute `bundle.crt` and reload hosts (they trust both, certs still signed by the old CA).
2. **Promote the new CA** to `default = true`. Hosts are re-signed under the new CA on the next run; distribute the new certs and reload.
3. **Archive the old CA** with `archived = true`. The bundle drops the old CA; distribute the slimmer `bundle.crt` and reload.
4. **Remove the archived block** (optional cleanup) once satisfied. The old CA's cert and key files remain on disk unmanaged after the block is removed; delete them manually if desired.

```hcl
# Stage 3: old CA archived, new CA is the sole signer.
ca "old" {
  name     = "mesh-2025"
  archived = true        # excluded from bundle; barred from signing
}

ca "new" {
  name    = "mesh-2026"
  default = true
}
```

Full worked example in [`spec/hcl-schema.md`](./spec/hcl-schema.md#ca-rotation-example).

## Time-based renewal

Set `renew_before` on a CA (inherited by all its hosts) or on individual hosts. When a cert enters its renewal window, the next run re-signs it automatically:

```hcl
ca "mesh" {
  name         = "mesh-2026"
  renew_before = "720h"    # re-sign all hosts 30 days before expiry
}

host "edge" {
  networks     = ["10.42.2.1/16"]
  renew_before = "48h"     # this host re-signs with 2 days to spare instead
}
```

After every run, including no-op runs, the tool prints to stderr the earliest upcoming deadline and a "run again before \<date\>" hint. It's advisory only and does not affect exit codes or writes.

## Air-gapped signing

For hosts whose private key must never leave the device (phones, HSMs, or any
separation-of-duties setup) the device generates its own keypair and exports
only the public key. Point `in_pub` at that file; `nebula-pki` signs it and
writes only the cert. No private key is generated, stored, or encrypted.

```hcl
host "alice_phone" {
  networks = ["10.42.5.20/16"]
  groups   = ["mobile"]
  in_pub   = "./inbox/alice_phone.pub"   # device-exported public key
  # no out_key; only alice_phone.crt is written
}
```

`in_pub` is mutually exclusive with `out_key` and is a validation error together with it. The key's curve must match the signing CA. Renewal re-signs the same public key. See [ADR-018](./spec/adr/018-in-pub-air-gapped-signing.md).

## Encryption at rest (opt-in) 🚧

> This section is under **active development.** Do not rely on this in production yet.

By default, CA and host private keys land on disk as plaintext, which means you cannot safely keep `out/` in git. The optional `storage.encryption "sops"` block writes every private key through the [sops](https://github.com/getsops/sops) CLI before touching disk. Certificates, the trust bundle, and the manifest are never encrypted.

`sops` must be installed and available (in `PATH`) on any machine running `nebula-pki` with `sops` encryption enabled.

### Inline recipients

List one or more age, PGP, or KMS recipients directly in the config. sops uses them to encrypt; no `.sops.yaml` file is needed.

```hcl
storage {
  encryption "sops" {
    age = ["age1ylsajqmdg4kd7u7s6mn6vxt35llrrpwj7nj578qcsx78g72w8uhqdzstdt"]
  }
}
```

Keys are written with the configured suffix (default `.enc`): `out/ca/mesh.key.enc`, `out/hosts/alpha.key.enc`. Plaintext `.key` files are never written to disk.

### `.sops.yaml` discovery

Use an empty block and let sops discover `.sops.yaml` by searching upward from the output directory:

```hcl
storage {
  encryption "sops" {}
}
```

Place a `.sops.yaml` at the repo root or any ancestor of `out/`:

```yaml
creation_rules:
  - age: age1ylsajqmdg4kd7u7s6mn6vxt35llrrpwj7nj578qcsx78g72w8uhqdzstdt
```

### Decryption on rerun

When a CA key is already encrypted on disk, `nebula-pki` decrypts it in-memory — no plaintext file is written — and uses it to sign new or renewing hosts. Set `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, or the appropriate credential for your backend so sops can decrypt.

### Changing recipients

Changing the recipients in the config does **not** re-encrypt existing key files on a normal run. Instead, a warning is printed for every artifact whose recorded recipients differ from the current config:

```
warning: CA "mesh" key was encrypted with different recipients; run 'nebula-pki reencrypt' to re-encrypt
warning: host "alpha" key was encrypted with different recipients; run 'nebula-pki reencrypt' to re-encrypt
```

New hosts added in the same run are encrypted with the current (new) recipients. Existing files are left under the old recipients until `nebula-pki reencrypt` is run.

This is intentional: silently re-encrypting a CA private key on a routine `nebula-pki` run is risky — a crash between decrypt and re-encrypt can leave the key unrecoverable. The explicit `reencrypt` command makes recipient rotation a deliberate, audited step.

### Switching backends (`none` → `sops`)

Enabling `sops` after a plaintext run is detected as a configuration mismatch. `nebula-pki` errors immediately rather than creating a mix of encrypted and plaintext files:

```
ca "mesh": encryption configuration changed: CA key exists at out/ca/mesh.key
(recorded in manifest) but current config expects it at out/ca/mesh.key.enc;
use `nebula-pki reencrypt` to migrate between encryption configs, or manually
move/rename the key file to the expected path
```

Run `nebula-pki reencrypt` to encrypt the existing keys in place and update the manifest. *(Subcommand ships in a later release.)*

## CLI

```sh
nebula-pki                # reconcile out/ with nebula.hcl  (default action)
nebula-pki --dry-run      # preview what would change; no writes
nebula-pki check          # parse and validate nebula.hcl; no I/O against out/
nebula-pki -c other.hcl   # use a different config path
```

`--dry-run` prints the planned writes to stdout and still prints the deadline advisory to stderr, the same as a normal run.

## Consuming from Terraform

Use `output_dir` to place certs where your Terraform modules expect them, then read them with `file()`:

```hcl
resource "some_provider_file" "nebula_cert" {
  content = file("${path.module}/../nebula/out/hetzner/app_hetzner_01.crt")
}
```

## Further reading

- Full HCL reference, encryption backends, CA reference mode, host options: [`hcl-schema.md`](./spec/hcl-schema.md).
- Building, testing, releasing: [`development.md`](./development.md).
- Design rationale and decisions: [`spec/`](./spec/readme.md).
- Upstream Nebula: <https://github.com/slackhq/nebula>.

---

_Copyright (c) 2026 The nebula-pki Authors. Licensed under the MIT License. See [`LICENSE`](./LICENSE)._
