# Encryption strategy

* Status: accepted
* Deciders: fw
* Date: 2026-05-18

## Context and Problem Statement

Private key material must be safe to commit to a (private) git repository and safe to leave on the operator's workstation. We want encryption at rest to be the default behaviour for serious use, while keeping the tool friendly for newcomers and for users who already have their own secrets workflow.

## Decision Drivers

* Encryption must be straightforward enough that the recommended path "just works".
* Users must be able to opt out, or to plug in their own tool, without recompiling.
* The chosen library/format must be widely understood and well-maintained.
* If the operator already manages sops config in `.sops.yaml` (the canonical sops workflow), nebula-pki must honour it without forcing a second source of truth.
* Encrypted files should remain inspectable enough to diff cleanly (metadata changes only, ciphertext changes only on real key changes).
* No new long-running services or daemons.

## Considered Options

* A. Encrypt only via the `sops` CLI subprocess.
* B. Encrypt via the [`getsops/sops`](https://github.com/getsops/sops) Go library, in-process.
* C. Make encryption a pluggable backend with at least `none`, built-in `sops`, and `external` (arbitrary command). See ADR-006 for the extensibility model.

## Decision Outcome

Chosen option: **C, with the built-in sops backend implemented via option B (in-process library) and behaving exactly like the sops CLI.** This gives a smooth out-of-the-box experience while letting operators reuse their existing sops setup.

Specifically:

- `encryption "none" {}` is the default. The tool ships and runs without any encryption configured.
- `encryption "sops" { ... }` uses the sops Go library directly. **All sops key types are supported** — age, PGP, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit — exposed as optional HCL fields that map 1:1 to sops CLI flags.
- When the HCL block has no recipients configured, the sops library performs its standard upward search for `.sops.yaml` and applies whichever `creation_rules` match the output path. The HCL block can be empty (`encryption "sops" {}`) when `.sops.yaml` is authoritative.
- When the HCL block lists recipients explicitly, they take precedence over `.sops.yaml` for files written by nebula-pki — same precedence rules as `sops -e --age ... --pgp ...` on the CLI.
- `encryption "external" { encrypt_command = [...], decrypt_command = [...] }` invokes a user-supplied command. Placeholders `{{.In}}` and `{{.Out}}` are substituted at invocation time.
- Only **private key files** are encrypted. Public certificates, QRs, and the manifest stay plaintext.

### Positive Consequences

* Single static binary; no `sops` CLI on PATH required.
* Operators with an existing `.sops.yaml` (e.g. one already using PGP) get zero-config integration.
* The default path is one line of HCL.
* All sops key types are supported on day one; no future schema break to add KMS or Vault.

### Negative Consequences

* Embedding the sops library bloats the binary (a few MB).
* We track sops library breaking changes.
* Two code paths for encryption (library vs. subprocess) need testing.

## Pros and Cons of the Options

### A. Sops CLI subprocess only

* Good, because it is the simplest implementation.
* Good, because users probably already have sops installed.
* Bad, because it requires `sops` on PATH for the *recommended* path, which contradicts the "easy to get started" goal.
* Bad, because subprocess error handling is noisier than library calls.

Rejected as the default; retained as the model for the `external` backend.

### B. Sops Go library in-process

* Good, because no external dependency for the recommended path.
* Good, because errors and diagnostics are first-class Go values.
* Good, because the library reads `.sops.yaml` natively via the same code path as the CLI.
* Bad, because of binary size and library version coupling.

Accepted as the implementation of the built-in `sops` backend.

### C. Pluggable backends (none / sops / external)

* Good, because it satisfies opt-in, bring-your-own, and zero-config use cases simultaneously.
* Good, because adding new built-in backends later is non-breaking.
* Bad, because it is more design surface than a hardcoded single backend.

Accepted. See ADR-006 for the extensibility shape.

## What gets encrypted

Only **private key files** are encrypted. Specifically: CA private keys (generate mode, written as `<label>.key<suffix>`) and host private keys (written as `<host.name>.key<suffix>`). Nothing else is encrypted:

- **Public certificates (`.crt`)** are not secret material in Nebula's design. Hosts broadcast them during connection establishment; they are meant to be distributed. Encrypting them would add decryption overhead to every downstream consumer (Terraform `file()`, Ansible copy tasks, etc.) with no security benefit.
- **The trust bundle** (`bundle.crt`) is a concatenation of CA public certs — equally public.
- **The manifest** (`nebula-pki.json`) is designed to contain no secret material. Fingerprints are public identifiers; artifact paths are structural metadata.
- **QR PNGs** contain public key material only.

Operators who want to protect certificate metadata (network topology, group memberships visible in `.crt` files) should do so at the git-repository level (private repo, signed commits) or filesystem level — this is outside the tool's scope.

## Decryption on reuse

When a CA is in generate mode and its key was written encrypted in a previous run, subsequent runs must decrypt the key before using it to sign hosts. The active backend's `Decrypt` method is called in-memory; no plaintext temp file is written to disk. This means the operator's decryption credentials (age private key, PGP keyring, AWS IAM role, etc.) must be present in the environment on every reconcile run, not only at CA generation time. This constraint is documented in `hcl-schema.md` under the `encryption "sops"` and `encryption "external"` block references.

## Recipient-mismatch warning

Changing the `age`, `pgp`, or other recipient fields in the HCL between runs does **not** trigger automatic re-encryption of existing key files. Key files are only (re-)written when the key material itself changes (new generation or renewal). This keeps normal runs side-effect-free and avoids silently rewriting secrets when config is edited.

When the tool detects that an existing encrypted key file's metadata (embedded sops recipient list, or the `encrypt_command` for the `external` backend) differs from the currently configured recipients, it prints a warning on stderr on **every** run until the mismatch is resolved:

```
warning: out/hosts/app_01.key.enc was encrypted with different recipients than currently configured.
         Run 'nebula-pki rekey' to re-encrypt with the current recipients.
```

The warning is persistent so operators do not forget about a partial or mixed encryption state. It is cleared once `nebula-pki rekey` successfully re-encrypts all affected files. The manifest stores a fingerprint of the recipients/command used to encrypt each file; this is what the mismatch check compares against.

## Links

* ADR-001 — tooling approach.
* ADR-006 — storage backend extensibility.
* [Milestone v0.2](../milestones/v0.2.md) — encryption iteration plan and decisions D-1 through D-3.
* [getsops/sops](https://github.com/getsops/sops)
* [sops `.sops.yaml` config](https://github.com/getsops/sops#using-sopsyaml-conf-to-select-kmspgp-for-new-files)
* [age](https://github.com/FiloSottile/age)
