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

Chosen option: **C, with the built-in sops backend implemented via option A (CLI subprocess) and behaving exactly like the sops CLI.** This gives first-class sops integration while keeping the binary lean.

Specifically:

- `encryption "none" {}` is the default. The tool ships and runs without any encryption configured.
- `encryption "sops" { ... }` shells out to the `sops` binary. **All sops key types are supported** — age, PGP, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit — exposed as optional HCL fields that map 1:1 to sops CLI flags. The `sops` binary must be in PATH when this backend is active.
- When the HCL block has no recipients configured, sops performs its standard upward search for `.sops.yaml` from the output file's directory. The HCL block can be empty (`encryption "sops" {}`) when `.sops.yaml` is authoritative.
- When the HCL block lists recipients explicitly, they are passed as flags to sops and take precedence over `.sops.yaml` for files written by nebula-pki — same precedence rules as `sops --encrypt --age ... --pgp ...`.
- `encryption "external" { encrypt_command = [...], decrypt_command = [...] }` invokes a user-supplied command. Placeholders `{{.In}}` and `{{.Out}}` are substituted at invocation time.
- Only **private key files** are encrypted. Public certificates, QRs, and the manifest stay plaintext.

### Positive Consequences

* Binary remains small; no transitive SDK dependencies (no AWS/GCP/Azure SDK embedded).
* Operators with an existing `.sops.yaml` get zero-config integration — they already have sops installed.
* The default path is one line of HCL.
* All sops key types are supported on day one via the sops CLI flags.

### Negative Consequences

* `sops` binary must be present in PATH when using this backend.
* Subprocess error handling is noisier than library calls (stderr captured and re-emitted).
* During encryption a plaintext temp file (`.nebula-pki-plain-*`) is written to the output directory so sops can discover `.sops.yaml`. A `defer os.Remove` cleans it up on normal exit; SIGKILL or power loss can leave it behind. `nebula-pki` sweeps these files at the start of the next run (see §"Plaintext temp file during encryption").

## Pros and Cons of the Options

### A. Sops CLI subprocess only

* Good, because no transitive SDK dependencies; binary stays lean.
* Good, because users who choose `encryption "sops"` almost certainly have sops installed.
* Good, because `.sops.yaml` discovery is native to the sops binary — no re-implementation needed.
* Bad, because requires `sops` on PATH; the tool can't run in environments without sops.
* Bad, because subprocess error handling is noisier than library calls.

Accepted as the implementation of the built-in `sops` backend.

### B. Sops Go library in-process

* Good, because no external binary required for the recommended path.
* Good, because errors and diagnostics are first-class Go values.
* Good, because the library reads `.sops.yaml` natively via the same code path as the CLI.
* Bad, because embedding the Go library pulls in AWS SDK, GCP SDK, Azure SDK, and HashiCorp Vault SDK as transitive dependencies regardless of which key types the operator actually uses — significant binary bloat.
* Bad, because we track sops library breaking changes.

Rejected in favour of option A. The "easy to get started" goal is still met: any operator configuring `encryption "sops"` is already a sops user and has the binary. The `external` backend covers the general "shell out to any command" use case.

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

When a CA is in generate mode and its key was written encrypted in a previous run, subsequent runs must decrypt the key before using it to sign hosts. For the `sops` backend, `sops --decrypt` is invoked; for `external`, the configured `decrypt_command` is run. The operator's decryption credentials (age private key, GPG keyring, AWS IAM role, etc.) must be present in the environment on every reconcile run that triggers a host re-sign, not only at CA generation time. This constraint is documented in `hcl-schema.md` under the `encryption "sops"` and `encryption "external"` block references.

No plaintext temp file is written to disk during decryption: the decrypted bytes are piped through stdout directly into memory.

## Plaintext temp file during encryption

The sops backend must write the key material to a temporary file in the target output directory before invoking `sops --encrypt`. This lets sops perform its standard upward search for `.sops.yaml` from the correct location. The file is created with mode `0o600` (owner-only read/write) and removed via `defer` immediately after sops returns.

A `defer os.Remove` does not execute when the process is killed with SIGKILL, by the OOM killer, or by a hardware power loss. In those cases a `.nebula-pki-plain-*` file containing plaintext key material is left in the output directory.

**Mitigation — startup sweep:** On every real reconcile run (not `--dry-run`), `nebula-pki` walks the standard output tree (`storage.out_dir`) and removes any `.nebula-pki-plain-*` files before doing any other work. This makes the SIGKILL case self-healing on the next run.

**Known gap:** per-host `output_dir` values set to an absolute path outside `storage.out_dir` are not included in the sweep. Operators using custom output dirs should verify no orphaned files remain after an abnormal exit.

This is a known limitation of the CLI subprocess approach — it does not apply to the `none` backend and will not apply to the `external` backend either, since those do not require a plaintext input file on disk.

## Manifest encryption metadata

The manifest stores, per encrypted artifact (key file):

- `encryption.backend` — `"sops"` or `"external"`.
- `encryption.recipients_sha` — SHA-256 of the sorted configured recipient strings (e.g. `"age:<pubkey>"`, `"pgp:<fp>"`). Empty when no inline recipients are configured (i.e., `.sops.yaml` is authoritative). Used by the mismatch warning (see below).
- `encryption.suffix` — the `output_suffix` value that was active when the file was written (e.g. `".enc"`). Stored so that the tool can locate existing encrypted files even if `output_suffix` is later reconfigured.

The artifact's `key_path` always records the path as it exists on disk (including the suffix), e.g. `"out/ca/mesh.key.enc"`.

## Recipient-mismatch warning

Changing the `age`, `pgp`, or other recipient fields in the HCL between runs does **not** trigger automatic re-encryption of existing key files. Key files are only (re-)written when the key material itself changes (new generation or renewal). This keeps normal runs side-effect-free and avoids silently rewriting secrets when config is edited.

When the tool detects that an existing encrypted key file's metadata (embedded sops recipient list, or the `encrypt_command` for the `external` backend) differs from the currently configured recipients, it prints a warning on stderr on **every** run until the mismatch is resolved:

```
warning: out/hosts/app_01.key.enc was encrypted with different recipients than currently configured.
         Run 'nebula-pki reencrypt' to re-encrypt with the current recipients.
```

The warning is persistent so operators do not forget about a partial or mixed encryption state. It is cleared once `nebula-pki reencrypt` successfully re-encrypts all affected files. The manifest stores a fingerprint of the recipients/command used to encrypt each file; this is what the mismatch check compares against.

## Links

* ADR-001 — tooling approach.
* ADR-006 — storage backend extensibility.
* [Milestone v0.2](../milestones/v0.2.md) — encryption iteration plan and decisions D-1 through D-3.
* [getsops/sops](https://github.com/getsops/sops)
* [sops `.sops.yaml` config](https://github.com/getsops/sops#using-sopsyaml-conf-to-select-kmspgp-for-new-files)
* [age](https://github.com/FiloSottile/age)
