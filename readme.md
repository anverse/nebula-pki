# nebula-pki

`nebula-pki` is a declarative layer over [`nebula-cert`](https://github.com/slackhq/nebula).
Describe the Nebula network in one config; automatically generate and sign the certificates.

Without it, managing a Nebula network means running `nebula-cert` commands by hand: per-cert flags, signing sessions in shell history, no record of what changed or when.

`nebula-pki` replaces that with an HCL config that describes every CA and cert in one place.
After every run it writes `nebula-pki.json` with CA fingerprints, cert windows, and signing CA labels.
Changes flow through pull requests with a complete, readable diff.

> nebula-pki is under active development. It's ready to use day-to-day, but breaking changes may still happen before v1.0.

**Contents**

- [Install](#install)
- [Getting Started](#getting-started)
- [CA rotation, step by step](#ca-rotation)
- [Config reference](#config-reference)
  - [The `ca` block](#the-ca-block)
    - [Reference mode: use an existing CA](#reference-mode)
    - [A CA is pinned to its label](#pinned-to-its-label)
    - [CA cert links: symlink the CA cert into output directories](#ca-cert-links)
  - [The `cert` block](#the-cert-block)
    - [Output directory: place a cert and key per deploy target](#output-directory)
  - [The `trust_bundle` block](#the-trust_bundle-block)
- [Advanced](#advanced)
  - [Time-based renewal](#time-based-renewal)
  - [Air-gapped signing](#air-gapped-signing)
  - [Encryption at rest (opt-in)](#encryption-at-rest-opt-in)
  - [Consuming from Terraform](#consuming-from-terraform)
- [CLI](#cli)
- [Further reading](#further-reading)

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
ca "network_v1" {
  name     = "network-v1"
  networks = ["10.42.0.0/16"]
  duration = "8760h" # 365 days
}

trust_bundle "main" {
  ca_refs = [ca.network_v1]
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
It generates the CA on the first run, signs missing certs, writes the trust bundle, and updates the manifest at `out/nebula-pki.json`:

```
out/
  nebula-pki.json
  ca/
    network_v1.crt
    network_v1.key
  bundles/
    main.crt              ← pki.ca
  certs/
    lh_01.crt             ← pki.cert
    lh_01.key             ← pki.key
    node_01.crt
    node_01.key
```

The trust bundle is optional, but declaring it from the start gives every node's `pki.ca` one stable path that stays valid through a later [CA rotation](#ca-rotation). See [the `trust_bundle` block](#the-trust_bundle-block).

## CA rotation

Rotating a CA is four edits to `nebula.hcl`, each followed by a run of `nebula-pki`. The tool writes the files; distributing them and reloading nodes is up to you. In the configs below, a trailing comment marks each line that changed in that step.

**Starting point.** One CA, declared with a `trust_bundle` from the start (as in [Getting Started](#getting-started)), so every node's `pki.ca` points at `out/bundles/main.crt`:

```hcl
trust_bundle "main" {
  ca_refs = [ca.network_v1]
}

ca "network_v1" {
  name     = "network-v1"
  networks = ["10.42.0.0/16"]
}

cert "node_01" {
  networks = ["10.42.1.10/16"]
}
```

**Step 1: add the new CA and trust it.** Declare the new CA and add it to `ca_refs`. With two CAs, certs that don't set `ca` need a default to pick their signing CA (otherwise the run fails validation), so mark the old CA `default = true`. The run generates the new CA and rewrites `main.crt` with both CAs. Distribute `main.crt` and reload nodes: they now trust both CAs, and certs are still signed by the old one.

```hcl
trust_bundle "main" {
  ca_refs = [ca.network_v1, ca.network_v2]   # new CA added to the trust set
}

ca "network_v1" {
  name     = "network-v1"
  networks = ["10.42.0.0/16"]
  default  = true                            # old CA keeps signing
}

ca "network_v2" {                            # new CA
  name     = "network-v2"                    # new CA
  networks = ["10.42.0.0/16"]                # new CA
}

cert "node_01" {
  networks = ["10.42.1.10/16"]
}
```

**Step 2: sign with the new CA.** Move `default = true` to the new CA. The run re-signs every cert that doesn't set `ca` under the new CA. Distribute the new certs and reload. To canary first, set `ca = ca.network_v2` on a few certs before moving the default.

```hcl
trust_bundle "main" {
  ca_refs = [ca.network_v1, ca.network_v2]
}

ca "network_v1" {
  name     = "network-v1"
  networks = ["10.42.0.0/16"]
                                             # default removed
}

ca "network_v2" {
  name     = "network-v2"
  networks = ["10.42.0.0/16"]
  default  = true                            # new CA signs from now on
}

cert "node_01" {
  networks = ["10.42.1.10/16"]
}
```

**Step 3: stop trusting the old CA.** Drop the old CA from `ca_refs`. The run rewrites `main.crt` with only the new CA. Distribute it and reload. The old CA keeps its manifest record. Nothing stops it from signing, but after step 2 no cert uses it: keep it that way, since nodes no longer trust it.

```hcl
trust_bundle "main" {
  ca_refs = [ca.network_v2]                  # old CA removed from the trust set
}

ca "network_v1" {
  name     = "network-v1"
  networks = ["10.42.0.0/16"]
}

ca "network_v2" {
  name     = "network-v2"
  networks = ["10.42.0.0/16"]
  default  = true
}

cert "node_01" {
  networks = ["10.42.1.10/16"]
}
```

**Step 4: retire the old CA.** Delete the old `ca` block once satisfied. The run deletes its symlinks and drops its manifest record; its cert and key files stay on disk with a notice, for you to delete. A forgotten `ca.network_v1` reference fails the parse.

```hcl
trust_bundle "main" {
  ca_refs = [ca.network_v2]
}

                                             # ca "network_v1" block deleted

ca "network_v2" {
  name     = "network-v2"
  networks = ["10.42.0.0/16"]
  default  = true
}

cert "node_01" {
  networks = ["10.42.1.10/16"]
}
```

The configuration is now back to the starting shape, with the new CA. Full worked example in [`spec/hcl-schema.md`](./spec/hcl-schema.md#ca-rotation-example).

## Config reference

This is the reference for `nebula.hcl`: the blocks it is built from, their fields, and how nebula-pki treats them. The `storage` block (output root, manifest path, key encryption) is covered in [Encryption at rest](#encryption-at-rest-opt-in) and in [`spec/hcl-schema.md`](./spec/hcl-schema.md), which also lists every validation rule.

### The `ca` block

A `ca` block declares a signing CA. Every block carries a label (`ca "<label>" {}`), and a config may declare any number of them. By default the tool generates the CA itself (generate mode); setting `cert_file` and `key_file` uses an existing one instead ([reference mode](#reference-mode)).

Fields without a trailing comment are the `nebula-cert ca` flag of the same name, with underscores for dashes (`unsafe_networks` is `-unsafe-networks`); see `nebula-cert ca -h` for what they do. Fields with a trailing comment are added by nebula-pki.

```hcl
ca "network_v1" {
  # Identity
  name    = "network-v1"
  default = true                          # signing CA for certs that don't set `ca`

  # Validity
  duration     = "26280h"
  renew_before = "720h"                   # re-sign this CA's certs 30 days before they expire

  # Certificate format
  version = 2
  curve   = "25519"

  # Restrictions for the certs this CA signs
  groups          = ["lighthouse", "router"]
  networks        = ["10.42.0.0/16"]
  unsafe_networks = ["192.168.0.0/16"]

  # Output
  out_crt  = "out/ca/network.crt"
  out_key  = "out/ca/network.key"
  link_crt = ["out/hetzner", "out/aws"]   # symlink the CA cert into each directory
}
```

What nebula-pki adds:

| Field | Purpose |
|---|---|
| _label_ | The CA's identity: manifest key, target of `ca.<label>` references, and default file name. Unique ignoring case. |
| `default` | Picks the signing CA for certs that don't set `ca`. At most one CA may set it. |
| `renew_before` | Renewal window inherited by every cert this CA signs. See [Time-based renewal](#time-based-renewal). |
| `cert_file`, `key_file` | Use an existing CA instead of generating one. See [Reference mode](#reference-mode). |
| `link_crt` | Relative symlinks to the CA cert, one per directory. See [CA cert links](#ca-cert-links). |

`name` is required in generate mode. `out_crt` and `out_key` default to `<storage.out_dir>/ca/<label>.crt` and `.key`.

Each cert resolves to one signing CA: its `ca` reference if set, else the CA marked `default = true`, else the only CA when exactly one is declared. Anything else is a validation error. The `groups`, `networks` and `unsafe_networks` restrictions are checked against each cert signed by this CA.

> **Not implemented yet.** `encrypt = true` (a passphrase-encrypted CA key) fails the run; use [`storage.encryption`](#encryption-at-rest-opt-in) to encrypt keys at rest. `argon_memory`, `argon_iterations` and `argon_parallelism` are accepted but have no effect without it. `out_qr` is accepted, but no QR file is written.

#### Reference mode

```hcl
ca "shared_root" {
  cert_file = "/path/to/ca.crt"
  key_file  = "/path/to/ca.key"
}
```

Setting `cert_file` and `key_file` (both are required together) uses an existing CA. The tool only reads the files; it never rewrites them, and nothing is written to `out/ca/`. Generate-only fields (`name`, `duration`, `version`, `curve`, `encrypt`, `argon_*`, `out_*`) are rejected; `link_crt` works in both modes.

Before recording anything, the pair is verified: the certificate must be a CA with a valid self-signature, and the key must match its curve and public key. A missing file is an error. An expired referenced CA is recorded with a warning, since the CA belongs to you in this mode. `nebula-pki check` also reads the files and prints the CA fingerprint.

#### Pinned to its label

The manifest records each CA's fingerprint under its label, and `nebula-pki` never puts a different CA under a recorded label. The run and `--dry-run` fail before writing anything when:

- a referenced CA's certificate has a different fingerprint than recorded (a new CA at the same path, the wrong branch or environment),
- a generated CA's cert and key are both gone (it is not silently regenerated),
- a generated CA's certificate has a different fingerprint than recorded,
- a label was renamed only in case (`ca "network"` to `ca "Network"`), on every platform.

An encrypted CA key is checked against its certificate when it is decrypted to sign. Moving a referenced CA to another path is fine; only the recorded paths change.

To switch to a different CA, declare it under a new label (move `default = true`, update `ca_refs`); its certs are then re-signed. To start from scratch, delete all of `out/`, manifest included.

**Deleting a `ca` block** deletes its `link_crt` symlinks and drops its manifest record. A generated CA's cert and key stay on disk with a notice that they are no longer managed; a referenced CA's files were never managed, so there is no notice.

#### CA cert links

When certs are fanned out to per-provider directories via [`output_dir`](#output-directory), each directory also needs the CA certificate for its nodes to authenticate against. The CA cert lives under `out/ca/`; it doesn't follow `output_dir` automatically.

Use `link_crt` on a `ca` block to place a relative symlink of the CA certificate into each directory that needs it:

```hcl
ca "network" {
  name     = "network-v1"
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
  ca/network.crt           ← actual CA certificate
  hetzner/
    lh_fra.crt
    lh_fra.key
    network.crt → ../ca/network.crt   ← symlink
  aws/
    app_01.crt
    app_01.key
    network.crt → ../ca/network.crt   ← symlink
```

**Symlink name** is the CA cert filename: `<label>.crt` by default, or the basename of `out_crt` when that is set. This is the same name across the CA cert file and all its links.

**Relative targets:** symlink targets are always relative (computed via `filepath.Rel`), so they survive `git clone` to any absolute path on any machine. The link `out/hetzner/network.crt` stores `../ca/network.crt` as its target, not an absolute path.

**Idempotency:** a re-run is a no-op when the symlink already points to the correct target. A broken or wrong-target symlink is recreated. A regular file at a declared link path is an error (never clobbered).

**Stale cleanup:** removing a directory from `link_crt`, or deleting the whole `ca` block, causes the old symlink to be deleted on the next run. If a regular file now occupies the path, a notice is printed and the file is left alone.

The manifest records each managed link under `cas.<label>.links` so the tool can detect stale links across runs.

A single CA's link is only correct until the CA rotates. For `pki.ca`, prefer a [trust bundle's `link_crt`](#the-trust_bundle-block), whose content stays correct before, during, and after a rotation.

### The `cert` block

A `cert` block declares one node certificate, the equivalent of one `nebula-cert sign` call.

Fields without a trailing comment are the `nebula-cert sign` flag of the same name, with underscores for dashes; see `nebula-cert sign -h` for what they do. Fields with a trailing comment are added by nebula-pki.

```hcl
cert "router" {
  # Identity
  name   = "router.network"
  groups = ["router"]

  # Addresses
  networks        = ["10.42.2.1/16"]
  unsafe_networks = ["192.168.10.0/24"]

  # Signing
  ca           = ca.network_v1            # signing CA; omit to use the default CA
  duration     = "8760h"
  renew_before = "48h"                    # overrides the signing CA's renew_before

  # Output
  output_dir = "out/routers"              # directory for the cert and key; default out/certs
  out_crt    = "router.crt"
  out_key    = "router.key"

  # Air-gapped signing: sign a device-held public key instead (no out_key then)
  # in_pub = "./inbox/router.pub"
}
```

What nebula-pki adds or does differently:

| Field | Purpose |
|---|---|
| _label_ | The cert's identity: manifest key, and the cert name when `name` is not set. Unique ignoring case. |
| `ca` | Reference to the signing CA (`ca = ca.network_v1`, not a quoted string). Omit it to use the default CA; see [the `ca` block](#the-ca-block). |
| `renew_before` | Re-sign this cert when it is this close to expiry. See [Time-based renewal](#time-based-renewal). |
| `output_dir` | Directory for the cert and key. See [Output directory](#output-directory). |
| `name` | Optional; defaults to the label. Set it when the name needs characters an HCL label can't carry (`edge-router.network`). Cert names are unique ignoring case. |
| `out_crt`, `out_key` | File names joined onto `output_dir`, not standalone paths. They default to `<name>.crt` and `<name>.key`. |

The certificate format version and curve come from the signing CA. `in_pub` is covered in [Air-gapped signing](#air-gapped-signing).

> **Not implemented yet.** `out_qr` is accepted, but no QR file is written.

#### Output directory

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

`out_crt` and `out_key` compose with `output_dir` rather than overriding it: a bare filename stays in the directory, a relative sub-path nests inside it. Without `output_dir`, files land in `<storage.out_dir>/certs`. To give each directory the CA certificate too, use [CA cert links](#ca-cert-links) or a [trust bundle's `link_crt`](#the-trust_bundle-block).

### The `trust_bundle` block

A Nebula node's `pki.ca` must contain every CA it should trust. A `trust_bundle` block writes that file: a concatenated PEM of the CA certificates it lists, with no key material. The block is nebula-pki's own; `nebula-cert` has no equivalent.

```hcl
trust_bundle "main" {
  ca_refs  = [ca.network_v1, ca.network_v2]   # required; members in bundle order
  path     = "out/bundles/main.crt"           # default <storage.out_dir>/bundles/<label>.crt
  link_crt = ["out/hetzner", "out/aws"]       # main.crt symlink in each directory
}
```

| Field | Required | Description |
|---|---|---|
| `ca_refs` | yes | The member CAs as `ca.<label>` references, written to the bundle in this order. Must be non-empty, without duplicates, and every reference must name a declared `ca` block. |
| `path` | no | Where the bundle is written. Defaults to `<storage.out_dir>/bundles/<label>.crt`. Relative paths resolve against the config file's directory. |
| `link_crt` | no | Directories that get a relative symlink to the bundle, named after the basename of `path` (`<label>.crt` by default). Same behaviour as [CA cert links](#ca-cert-links). |

**No block, no bundle.** Bundles are fully declarative: without a `trust_bundle` block no bundle is written and the manifest has no `trust_bundles` record. You can point `pki.ca` at a CA certificate directly instead. If the network may ever rotate its CA, declare a bundle from the start, even with a single member: `pki.ca` then keeps one stable path, and the bundle's symlinks stay correct through the whole [rotation](#ca-rotation). With a single member the bundle equals that CA's certificate.

**Several bundles.** A config may declare any number of `trust_bundle` blocks, for example separate trust sets for lighthouses and for clients. A CA can be a member of several bundles or of none. Labels must be unique ignoring case.

**Bundles describe trust, not signing.** Any declared CA may sign certs, in a bundle or not; `default = true` on a `ca` block picks the signing CA for certs that don't set `ca`. Keeping signing in step with what nodes trust is your job; during a rotation, moving `default = true` is what stops the old CA from signing.

**The label is the identity.** It names the file (`trust_bundle "main"` writes `main.crt`) and is the key in the manifest's `trust_bundles` map. Renaming a label, removing a block, or changing `path` writes the new bundle (if any) and leaves the old file on disk with a notice that it is no longer managed, unless the new bundle writes the same path. The old symlinks are deleted, except where a current block declares the same symlink path.

**Links next to CA links.** A `ca` block's `link_crt` and a bundle's `link_crt` may name the same directory as long as the file names differ (`network_v1.crt` and `main.crt`). Every path the tool writes must be unique ignoring case; a clash is an error naming every owner.

## Advanced

### Time-based renewal

Set `renew_before` on a CA (inherited by all its certs) or on individual certs. When a cert enters its renewal window, the next run re-signs it automatically:

```hcl
ca "network" {
  name         = "network-v1"
  renew_before = "720h"    # re-sign all certs 30 days before expiry
}

cert "edge" {
  networks     = ["10.42.2.1/16"]
  renew_before = "48h"     # this cert re-signs with 2 days to spare instead
}
```

A `renew_before` that is not shorter than the validity it applies to is an error. `--no-renewal` skips time-based renewal for one run; other re-sign triggers still apply.

After every run, including no-op runs, the tool prints to stderr the earliest upcoming deadline and a "run again before \<date\>" hint. It's advisory only and does not affect exit codes or writes.

### Air-gapped signing

For certs whose private key must never leave the device (phones, HSMs, or any separation-of-duties setup), the device generates its own keypair and exports only the public key. Point `in_pub` at that file; `nebula-pki` signs it and writes only the cert. No private key is generated, stored, or encrypted.

```hcl
cert "alice_phone" {
  networks = ["10.42.5.20/16"]
  groups   = ["mobile"]
  in_pub   = "./inbox/alice_phone.pub"   # device-exported public key
  # no out_key; only alice_phone.crt is written
}
```

`in_pub` is mutually exclusive with `out_key` and is a validation error together with it. The key's curve must match the signing CA. Renewal re-signs the same public key. See [ADR-018](./spec/adr/018-in-pub-air-gapped-signing.md).

### Encryption at rest (opt-in)

By default, CA and cert private keys land on disk as plaintext. The optional `storage.encryption` block encrypts every private key before it touches disk. Certificates, trust bundles, and the manifest are **never** encrypted.

Three backends are available:

| Backend | When to use |
|---|---|
| `none` | Default. Keys are plaintext. Skip the block entirely or declare it explicitly. |
| `sops` | Uses [sops](https://github.com/getsops/sops). First-class support for age, PGP, KMS, and `.sops.yaml` discovery. |
| `external` | Bring your encryption tool. `age` directly, `gpg`, `openssl`, a custom KMS wrapper, or any command that reads/writes on stdin/stdout. |

#### No encryption (default)

Omit the `encryption` block (or declare `encryption "none" {}`) and keys are written as plaintext. This is the right choice for local development or when your repo is already private and the threat model doesn't require key encryption.

#### sops

`sops` must be installed and in `PATH` on every machine running `nebula-pki` with this backend active, both for initial key generation (encrypt) and for any reconcile that signs certs under an existing encrypted CA key (decrypt).

**Inline recipients.** List one or more age, PGP, or KMS recipients directly in the config. sops uses them to encrypt; no `.sops.yaml` file is needed.

```hcl
storage {
  encryption "sops" {
    age = ["age1ylsajqmdg4kd7u7s6mn6vxt35llrrpwj7nj578qcsx78g72w8uhqdzstdt"]
  }
}
```

Keys are written with the configured suffix (default `.enc`): `out/ca/network.key.enc`, `out/certs/alpha.key.enc`. Plaintext `.key` files are never written to disk.

**`.sops.yaml` discovery.** Use an empty block and let sops discover `.sops.yaml` by searching upward from the output directory:

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

**Decryption on rerun.** When a CA key is already encrypted on disk, `nebula-pki` decrypts it in memory (no plaintext file is written) and uses it to sign new or renewing certs. Set `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, or the appropriate credential for your backend so sops can decrypt.

**Changing recipients.** Changing the recipients in the config does **not** re-encrypt existing key files on a normal run. Instead, a warning is printed for every artifact whose recorded recipients differ from the current config:

```
warning: CA "network" key was encrypted with different recipients; run 'nebula-pki rekey' to re-encrypt
warning: cert "alpha" key was encrypted with different recipients; run 'nebula-pki rekey' to re-encrypt
```

New certs added in the same run are encrypted with the current (new) recipients. Existing files are left under the old recipients until `nebula-pki rekey` is run.

This is intentional: silently re-encrypting a CA private key on a routine run is risky, because a crash between decrypt and re-encrypt can leave the key unrecoverable. The explicit `rekey` command makes rotation a deliberate, audited step.

#### External command

The `external` backend invokes operator-supplied commands to encrypt and decrypt key files. Use it when you want to use a tool that isn't sops, or when you need to pass flags the built-in sops backend doesn't expose.

**How data flows.** Two placeholders control how nebula-pki passes data to your commands:

| Placeholder | Where it works | What it becomes |
|---|---|---|
| `{{.InPath}}` | `encrypt_command`, `decrypt_command` | Absolute path to a temp file containing the input bytes (plaintext for encrypt, ciphertext for decrypt). |
| `{{.OutPath}}` | `encrypt_command` only | Absolute path to a temp file where the command must write its output. Ciphertext is read from this file after the command exits. |

When a placeholder is **absent**, the corresponding data flows via stdin (input) or stdout (output). Decrypt always reads its output from stdout; `{{.OutPath}}` is not substituted in `decrypt_command`.

Both `encrypt_command` and `decrypt_command` are required.

**age** uses `{{.InPath}}` for input and stdout for output:

```hcl
storage {
  encryption "external" {
    encrypt_command = ["age", "--encrypt", "--recipient", "age1...", "{{.InPath}}"]
    decrypt_command = ["age", "--decrypt", "--identity", "./age.key", "{{.InPath}}"]
  }
}
```

**openssl** uses `{{.InPath}}` + `{{.OutPath}}` for encrypt, and `{{.InPath}}` + stdout for decrypt:

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

**A stdin/stdout wrapper** uses no placeholders at all; data is piped in and out:

```hcl
storage {
  encryption "external" {
    encrypt_command = ["myencryptor", "--key-id", "prod-key"]
    decrypt_command = ["myencryptor", "--key-id", "prod-key", "--decrypt"]
  }
}
```

**sops via external** uses sops with full control over every flag:

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

**Changing the encrypt_command.** A SHA-256 hash of the full `encrypt_command` slice is recorded in the manifest alongside each encrypted key. When this hash changes between runs (a flag changed, a key ID rotated), the same mismatch warning as sops fires:

```
warning: CA "network" key was encrypted with different recipients; run 'nebula-pki rekey' to re-encrypt
```

No re-encryption happens automatically. Run `nebula-pki rekey` to rotate.

**Decryption on rerun.** When a CA key exists encrypted on disk, `nebula-pki` pipes the ciphertext to `decrypt_command` and reads plaintext from its stdout. No plaintext file is written to disk. Make sure any credentials your command needs (env vars, key files) are present on every machine that runs `nebula-pki`.

#### Switching backends

When the encryption suffix changes between runs (e.g. switching from `none` to `sops` or `external`), `nebula-pki` detects the mismatch and exits with an error rather than creating a mix of plaintext and encrypted files:

```
ca "network": encryption configuration changed: CA key exists at out/ca/network.key
(recorded in manifest) but current config expects it at out/ca/network.key.enc;
use `nebula-pki rekey` to migrate between encryption configs, or manually
move/rename the key file to the expected path
```

When switching between two backends that share the same suffix (e.g. `sops` → `external`, both defaulting to `.enc`), the run succeeds as a noop but the mismatch warning fires because the stored fingerprint no longer matches the current config. Run `nebula-pki rekey` to migrate.

#### `nebula-pki rekey`

`rekey` synchronizes the encryption of all managed private key files with the current storage backend config.

> **Note:** `rekey` operates on private key files at rest, the encryption configured under `storage { encryption ... }`. It has nothing to do with Nebula network certificates or tunnel encryption.

Run it whenever `nebula-pki` prints a mismatch warning, or after any change to the `encryption` block:

```sh
nebula-pki rekey            # process all files with a detectable mismatch
nebula-pki rekey --dry-run  # print what would change; no writes
nebula-pki rekey --force    # process all managed key files regardless of mismatch
```

**What it handles.** All three directions are handled in a single pass:

| Transition | When |
|---|---|
| Plaintext → encrypted | Storage encryption added to config since last run |
| Encrypted → re-encrypted | Recipients or backend changed |
| Encrypted → plaintext | `encryption` block removed (or set to `encryption "none" {}`) |

**Dry-run output:**

```
would encrypt CA "network" key: out/ca/network.key → out/ca/network.key.enc (sops)
would re-encrypt cert "alpha" key: out/certs/alpha.key.enc (sops, new recipients)
would decrypt cert "beta" key: out/certs/beta.key.enc → out/certs/beta.key (plaintext)
3 key files would be rekeyed.
```

**`.sops.yaml`-only mode.** When no inline recipients are configured in the `encryption "sops" {}` block, nebula-pki stores no `recipients_sha` in the manifest. It cannot detect a change to `.sops.yaml` between runs. After rotating keys in `.sops.yaml`, use `--force` to re-encrypt all managed key files:

```sh
nebula-pki rekey --force
```

**Removing encryption.** Removing the `encryption` block entirely is equivalent to setting `encryption "none" {}`. After removing it, `nebula-pki` will block the next reconcile with an "encryption configuration changed" error. Run `nebula-pki rekey` to decrypt all managed key files to plaintext; the following reconcile will proceed normally.

**Failure and recovery.** `rekey` aborts on the first error. Files already written in the same run are left on disk. The manifest is updated only when all files succeed. Re-running `rekey` is safe: already-matching files are skipped.

### Consuming from Terraform

Use `output_dir` to place certs where your Terraform modules expect them, then read them with `file()`:

```hcl
resource "some_provider_file" "nebula_cert" {
  content = file("${path.module}/../nebula/out/hetzner/app_hetzner_01.crt")
}
```

## CLI

```sh
nebula-pki                   # reconcile out/ with nebula.hcl (default action)
nebula-pki --dry-run         # preview what would change; no writes
nebula-pki --no-renewal      # skip time-based renewal; other re-sign triggers still apply
nebula-pki check             # parse and validate nebula.hcl; no I/O against out/
nebula-pki -c other.hcl      # use a different config path
nebula-pki rekey             # synchronize encryption of managed key files with current config
nebula-pki rekey --dry-run   # preview what rekey would change; no writes
nebula-pki rekey --force     # rekey all managed key files regardless of mismatch
nebula-pki --version         # print the version (also: nebula-pki version)
```

`check` reads referenced CA files and `in_pub` keys but nothing under `out/`. `--dry-run` prints the planned writes to stdout and still prints the deadline advisory to stderr, the same as a normal run.

Exit codes: `0` on success or a clean dry-run, `1` on a validation or runtime error, `2` on a usage error.

## Further reading

- Full HCL reference with every field, validation rules, and worked examples: [`hcl-schema.md`](./spec/hcl-schema.md).
- Building, testing, releasing: [`development.md`](./development.md).
- Design rationale and decisions: [`spec/`](./spec/readme.md).
- Upstream Nebula: <https://github.com/slackhq/nebula>.

---

_Copyright (c) 2026 The nebula-pki Authors. Licensed under the MIT License. See [`LICENSE`](./LICENSE)._
