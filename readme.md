# nebula-pki

`nebula-pki` is a declarative layer over [`nebula-cert`](https://github.com/slackhq/nebula).
Describe the Nebula network in one config; automatically generate and sign the certificates.

Without it, managing a Nebula network means running `nebula-cert` commands by hand: per-cert flags, signing sessions in shell history, no record of what changed or when.

`nebula-pki` replaces that with an HCL config that describes every CA and cert in one place.
After every run it writes `nebula-pki.json` with CA fingerprints, cert windows, and signing CA labels.
Changes flow through pull requests with a complete, readable diff.

> nebula-pki is under active development. It's ready to use day-to-day, but breaking changes may still happen before v1.0.

## Install

### Homebrew

```sh
brew install anverse/tap/nebula-pki
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

cert "lh_01" {
  networks = ["10.42.0.1/16"]
  groups   = ["lighthouse"]
}

cert "node_01" {
  networks = ["10.42.1.10/16"]
  groups   = ["node"]
}
```

```sh
nebula-pki
```

Declare one `cert` block per Nebula node. `nebula-pki` only issues the certificates and keys; it does not generate the node's Nebula `config.yaml`.

Running the tool reconciles `out/` with `nebula.hcl`.
It generates the CA if it doesn't exist, signs missing certs, and updates the manifest at `out/nebula-pki.json`.

## Per-cert output directory

Running a Nebula network that spans several Terraform projects, providers, or deploy targets? Each one usually only needs the certs for the nodes it owns. `output_dir` places a cert and its key in a specific directory so every downstream project reads from its own folder and sees nothing else.

```hcl
cert "lh_fra" {
  name       = "lh-fra"                 # cert CN; optional, defaults to label
  networks   = ["10.42.0.1/16"]
  output_dir = "out/third/party/vendor" # cert written to out/third/party/vendor/lh-fra.{crt,key}
}

cert "vendor_node_01" {
  networks   = ["10.42.1.10/16"]
  output_dir = "out/vendor"
}
```

Filenames default to `<cert.name>.crt` / `.key`. Use `out_crt` / `out_key` to rename them while keeping the same `output_dir`:

```hcl
cert "lh_fra" {
  networks   = ["10.42.0.1/16"]
  output_dir = "out/vendor"
  out_crt    = "nebula.crt"      # → out/vendor/nebula.crt
}
```

## CA cert links

When certs are fanned out to per-provider directories via `output_dir`, each directory also needs the CA certificate for its nodes to authenticate against. The CA cert lives under `out/ca/` — it doesn't follow `output_dir` automatically.

Use `link_crt` on a `ca` block to place a relative symlink of the CA certificate into each directory that needs it:

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

After `nebula-pki`, each output directory contains both the cert/key pair and a symlink to the CA cert:

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

**Stale cleanup** — removing a directory from `link_crt`, or deleting the whole `ca` block, causes the old symlink to be deleted on the next run. If a regular file now occupies the path, a notice is printed and the file is left alone.

The manifest records each managed link under `cas.<label>.links` so the tool can detect stale links across runs.

## Trust bundles

A `trust_bundle` block writes a concatenated PEM of the CA certificates it lists, suitable for `pki.ca` in each node's Nebula `config.yaml`. The file is named after the label: `trust_bundle "main"` writes `out/bundles/main.crt`. Membership is explicit: `ca_refs` lists the trusted CAs by reference, and the bundle holds them in that order.

```hcl
trust_bundle "main" {
  ca_refs  = [ca.current]
  path     = "out/bundles/main.crt"         # default
  link_crt = ["out/hetzner", "out/aws"]     # main.crt symlink in each directory
}
```

Without a `trust_bundle` block no bundle is written; point `pki.ca` at a CA certificate directly. If the network may ever rotate its CA, declare a bundle from the start, even with a single CA: `pki.ca` then keeps one stable path, and the bundle's `link_crt` symlinks stay correct through the whole rotation.

You can declare several bundles, for example a separate trust set for lighthouses and for clients, and a CA can be in any number of them. Bundles only describe trust: any declared CA may sign, in a bundle or not, and `default = true` just picks the signing CA for certs that don't set `ca`.

With a single member the bundle equals that CA's certificate. During rotation it holds both the old and new CA so nodes can authenticate against either.

The label is the bundle's identity. Renaming it, removing the block, or changing `path` writes the new bundle (if any) and leaves the old file on disk with a notice; the old symlinks are deleted.

## CA rotation

Rotating a CA is four edits to `nebula.hcl`, each followed by a rerun. Declare a `trust_bundle` before you start (see above).

1. **Add the new CA** and list it in `ca_refs`. The bundle now contains both; distribute `main.crt` and reload nodes (they trust both, certs still signed by the old CA).
2. **Promote the new CA** to `default = true`. Certs are re-signed under the new CA on the next run; distribute the new certs and reload.
3. **Drop the old CA from `ca_refs`.** The bundle shrinks to the new CA; distribute the slimmer `main.crt` and reload. The old CA keeps its manifest record; after step 2 no cert uses it, and since nodes no longer trust it, keep it that way.
4. **Delete the old `ca` block** once satisfied. Its symlinks are deleted; its cert and key files stay on disk with a notice, for you to delete.

```hcl
# Stage 3: only the new CA is trusted and signs.
trust_bundle "main" {
  ca_refs = [ca.new]
}

ca "old" {
  name = "mesh-2025"
}

ca "new" {
  name    = "mesh-2026"
  default = true
}
```

Full worked example in [`spec/hcl-schema.md`](./spec/hcl-schema.md#ca-rotation-example).

## Time-based renewal

Set `renew_before` on a CA (inherited by all its certs) or on individual certs. When a cert enters its renewal window, the next run re-signs it automatically:

```hcl
ca "mesh" {
  name         = "mesh-2026"
  renew_before = "720h"    # re-sign all certs 30 days before expiry
}

cert "edge" {
  networks     = ["10.42.2.1/16"]
  renew_before = "48h"     # this cert re-signs with 2 days to spare instead
}
```

After every run, including no-op runs, the tool prints to stderr the earliest upcoming deadline and a "run again before \<date\>" hint. It's advisory only and does not affect exit codes or writes.

## Air-gapped signing

For certs whose private key must never leave the device (phones, HSMs, or any
separation-of-duties setup) the device generates its own keypair and exports
only the public key. Point `in_pub` at that file; `nebula-pki` signs it and
writes only the cert. No private key is generated, stored, or encrypted.

```hcl
cert "alice_phone" {
  networks = ["10.42.5.20/16"]
  groups   = ["mobile"]
  in_pub   = "./inbox/alice_phone.pub"   # device-exported public key
  # no out_key; only alice_phone.crt is written
}
```

`in_pub` is mutually exclusive with `out_key` and is a validation error together with it. The key's curve must match the signing CA. Renewal re-signs the same public key. See [ADR-018](./spec/adr/018-in-pub-air-gapped-signing.md).

## Encryption at rest (opt-in)

By default, CA and cert private keys land on disk as plaintext. The optional `storage.encryption` block encrypts every private key before it touches disk. Certificates, the trust bundle, and the manifest are **never** encrypted.

Three backends are available:

| Backend | When to use |
|---|---|
| `none` | Default. Keys are plaintext. Skip the block entirely or declare it explicitly. |
| `sops` | Uses [sops](https://github.com/getsops/sops). First-class support for age, PGP, KMS, and `.sops.yaml` discovery. |
| `external` | Bring your encryption tool. `age` directly, `gpg`, `openssl`, a custom KMS wrapper, or any command that reads/writes on stdin/stdout. |

### No encryption (default)

Omit the `encryption` block (or declare `encryption "none" {}`) and keys are written as plaintext. This is the right choice for local development or when your repo is already private and the threat model doesn't require key encryption.

### sops

`sops` must be installed and in `PATH` on every machine running `nebula-pki` with this backend active — both for initial key generation (encrypt) and for any reconcile that signs certs under an existing encrypted CA key (decrypt).

#### Inline recipients

List one or more age, PGP, or KMS recipients directly in the config. sops uses them to encrypt; no `.sops.yaml` file is needed.

```hcl
storage {
  encryption "sops" {
    age = ["age1ylsajqmdg4kd7u7s6mn6vxt35llrrpwj7nj578qcsx78g72w8uhqdzstdt"]
  }
}
```

Keys are written with the configured suffix (default `.enc`): `out/ca/mesh.key.enc`, `out/certs/alpha.key.enc`. Plaintext `.key` files are never written to disk.

#### `.sops.yaml` discovery

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

#### Decryption on rerun

When a CA key is already encrypted on disk, `nebula-pki` decrypts it in-memory — no plaintext file is written — and uses it to sign new or renewing certs. Set `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, or the appropriate credential for your backend so sops can decrypt.

#### Changing recipients

Changing the recipients in the config does **not** re-encrypt existing key files on a normal run. Instead, a warning is printed for every artifact whose recorded recipients differ from the current config:

```
warning: CA "mesh" key was encrypted with different recipients; run 'nebula-pki rekey' to re-encrypt
warning: cert "alpha" key was encrypted with different recipients; run 'nebula-pki rekey' to re-encrypt
```

New certs added in the same run are encrypted with the current (new) recipients. Existing files are left under the old recipients until `nebula-pki rekey` is run.

This is intentional: silently re-encrypting a CA private key on a routine run is risky — a crash between decrypt and re-encrypt can leave the key unrecoverable. The explicit `rekey` command makes rotation a deliberate, audited step.

### External command

The `external` backend invokes operator-supplied commands to encrypt and decrypt key files. Use it when you want to use a tool that isn't sops, or when you need to pass flags the built-in sops backend doesn't expose.

#### How data flows

Two placeholders control how nebula-pki passes data to your commands:

| Placeholder | Where it works | What it becomes |
|---|---|---|
| `{{.InPath}}` | `encrypt_command`, `decrypt_command` | Absolute path to a temp file containing the input bytes (plaintext for encrypt, ciphertext for decrypt). |
| `{{.OutPath}}` | `encrypt_command` only | Absolute path to a temp file where the command must write its output. Ciphertext is read from this file after the command exits. |

When a placeholder is **absent**, the corresponding data flows via stdin (input) or stdout (output). Decrypt always reads its output from stdout; `{{.OutPath}}` is not substituted in `decrypt_command`.

Both `encrypt_command` and `decrypt_command` are required.

#### Examples

**age** — `{{.InPath}}` for input, stdout for output:

```hcl
storage {
  encryption "external" {
    encrypt_command = ["age", "--encrypt", "--recipient", "age1...", "{{.InPath}}"]
    decrypt_command = ["age", "--decrypt", "--identity", "./age.key", "{{.InPath}}"]
  }
}
```

**openssl** — `{{.InPath}}` + `{{.OutPath}}` for encrypt; `{{.InPath}}` + stdout for decrypt:

```hcl
storage {
  encryption "external" {
    encrypt_command = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2",
                       "-pass", "pass:secret",
                       "-in", "{{.InPath}}", "-out", "{{.OutPath}}"]
    decrypt_command = ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                       "-pass", "pass:secret",
                       "-in", "{{.InPath}}"]
  }
}
```

**stdin/stdout wrapper** — no placeholders at all; data piped in and out:

```hcl
storage {
  encryption "external" {
    encrypt_command = ["myencryptor", "--key-id", "prod-key"]
    decrypt_command = ["myencryptor", "--key-id", "prod-key", "--decrypt"]
  }
}
```

**sops via external** — uses sops but with full control over every flag:

```hcl
storage {
  encryption "external" {
    encrypt_command = ["sops", "--encrypt",
                       "--input-type", "binary", "--output-type", "binary",
                       "--age", "age1...", "{{.InPath}}"]
    decrypt_command = ["sops", "--decrypt",
                       "--input-type", "binary", "--output-type", "binary",
                       "{{.InPath}}"]
  }
}
```

#### Changing the encrypt_command

A SHA-256 hash of the full `encrypt_command` slice is recorded in the manifest alongside each encrypted key. When this hash changes between runs (a flag changed, a key ID rotated), the same mismatch warning as sops fires:

```
warning: CA "mesh" key was encrypted with different recipients; run 'nebula-pki rekey' to re-encrypt
```

No re-encryption happens automatically. Run `nebula-pki rekey` to rotate.

#### Decryption on rerun

When a CA key exists encrypted on disk, `nebula-pki` pipes the ciphertext to `decrypt_command` and reads plaintext from its stdout. No plaintext file is written to disk. Make sure any credentials your command needs (env vars, key files) are present on every machine that runs `nebula-pki`.

### Switching backends

When the encryption suffix changes between runs (e.g. switching from `none` to `sops` or `external`), `nebula-pki` detects the mismatch and exits with an error rather than creating a mix of plaintext and encrypted files:

```
ca "mesh": encryption configuration changed: CA key exists at out/ca/mesh.key
(recorded in manifest) but current config expects it at out/ca/mesh.key.enc;
use `nebula-pki rekey` to migrate between encryption configs, or manually
move/rename the key file to the expected path
```

When switching between two backends that share the same suffix (e.g. `sops` → `external`, both defaulting to `.enc`), the run succeeds as a noop but the mismatch warning fires because the stored fingerprint no longer matches the current config. Run `nebula-pki rekey` to migrate.

### `nebula-pki rekey`

`rekey` synchronizes the encryption of all managed private key files with the current storage backend config.

> **Note:** `rekey` operates on private key files at rest — the encryption configured under `storage { encryption ... }`. It has nothing to do with Nebula network certificates or tunnel encryption.

Run it whenever `nebula-pki` prints a mismatch warning, or after any change to the `encryption` block:

```sh
nebula-pki rekey            # process all files with a detectable mismatch
nebula-pki rekey --dry-run  # print what would change; no writes
nebula-pki rekey --force    # process all managed key files regardless of mismatch
```

#### What it handles

| Transition | When |
|---|---|
| Plaintext → encrypted | Storage encryption added to config since last run |
| Encrypted → re-encrypted | Recipients or backend changed |
| Encrypted → plaintext | `encryption` block removed (or set to `encryption "none" {}`) |

All three directions are handled in a single pass.

#### Dry-run output

```
would encrypt CA "mesh" key: out/ca/mesh.key → out/ca/mesh.key.enc (sops)
would re-encrypt cert "alpha" key: out/certs/alpha.key.enc (sops, new recipients)
would decrypt cert "beta" key: out/certs/beta.key.enc → out/certs/beta.key (plaintext)
3 key files would be rekeyed.
```

#### `.sops.yaml`-only mode

When no inline recipients are configured in the `encryption "sops" {}` block, nebula-pki stores no `recipients_sha` in the manifest. It cannot detect a change to `.sops.yaml` between runs.

After rotating keys in `.sops.yaml`, use `--force` to re-encrypt all managed key files:

```sh
nebula-pki rekey --force
```

#### Removing encryption

Removing the `encryption` block entirely is equivalent to setting `encryption "none" {}`. After removing it, `nebula-pki` will block the next reconcile with an "encryption configuration changed" error. Run `nebula-pki rekey` to decrypt all managed key files to plaintext; the following reconcile will proceed normally.

#### Failure and recovery

`rekey` aborts on the first error. Files already written in the same run are left on disk. The manifest is updated only when all files succeed. Re-running `rekey` is safe — already-matching files are skipped.

## CLI

```sh
nebula-pki                # reconcile out/ with nebula.hcl  (default action)
nebula-pki --dry-run      # preview what would change; no writes
nebula-pki check          # parse and validate nebula.hcl; no I/O against out/
nebula-pki -c other.hcl   # use a different config path
nebula-pki rekey          # synchronize encryption of managed key files with current config
nebula-pki rekey --dry-run   # preview what rekey would change; no writes
nebula-pki rekey --force     # rekey all managed key files regardless of mismatch
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

- Full HCL reference, encryption backends, CA reference mode, cert options: [`hcl-schema.md`](./spec/hcl-schema.md).
- Building, testing, releasing: [`development.md`](./development.md).
- Design rationale and decisions: [`spec/`](./spec/readme.md).
- Upstream Nebula: <https://github.com/slackhq/nebula>.

---

_Copyright (c) 2026 The nebula-pki Authors. Licensed under the MIT License. See [`LICENSE`](./LICENSE)._
