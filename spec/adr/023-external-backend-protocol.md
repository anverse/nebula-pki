# External backend command protocol

* Status: accepted
* Deciders: fw
* Date: 2026-07-16

## Context and Problem Statement

ADR-006 decided to ship an `external` encryption backend that invokes an operator-supplied command. That ADR focused on *why* the backend exists and left the command interface sketched as `{{.In}}` / `{{.Out}}` placeholders without a formal definition.

Before implementation, the protocol must be unambiguous on four questions:

1. How are placeholder names chosen to avoid confusion between "content" and "file path"?
2. What happens when an operator's command reads/writes via stdin/stdout instead of files?
3. Should the decrypt path be allowed to write plaintext to disk via a placeholder?
4. Must both `encrypt_command` and `decrypt_command` be present in the config?

## Decision Outcome

### D-1: Placeholder names are `{{.InPath}}` and `{{.OutPath}}`

The earlier sketch used `{{.In}}` and `{{.Out}}`. Those names suggest "content here" rather than "file path here." The `Path` suffix removes that ambiguity: every occurrence of `{{.InPath}}` or `{{.OutPath}}` in a command is substituted with an **absolute filesystem path** to a temporary file. A reader who sees `{{.InPath}}` in an HCL config immediately understands they are dealing with a path.

This supersedes the `{{.In}}` / `{{.Out}}` names that appeared in ADR-003 and ADR-006 examples.

### D-2: Stdin/stdout is the zero-config fallback

When `{{.InPath}}` is **absent** from the command, the tool pipes the input bytes to the command's stdin. When `{{.OutPath}}` is **absent** from `encrypt_command`, the tool captures the command's stdout as the output bytes.

This means a pure stdin/stdout tool (e.g. a custom wrapper script) requires no placeholder at all:

```hcl
encrypt_command = ["myencryptor", "--key-id", "prod-key"]
decrypt_command = ["myencryptor", "--key-id", "prod-key", "--decrypt"]
```

And a tool that needs files only on the input side uses only `{{.InPath}}`:

```hcl
encrypt_command = ["age", "--encrypt", "--recipient", "age1...", "{{.InPath}}"]
decrypt_command = ["age", "--decrypt", "--identity", "./age.key", "{{.InPath}}"]
```

The full matrix for `encrypt_command`:

| `{{.InPath}}` present | `{{.OutPath}}` present | Input | Output |
|---|---|---|---|
| no | no | stdin | stdout |
| yes | no | temp file | stdout |
| no | yes | stdin | temp file (read back) |
| yes | yes | temp file | temp file (read back) |

Temp files are created in `filepath.Dir(outputPath)` (for encrypt) and in the OS temp directory (for decrypt's ciphertext input). All temp files are removed via `defer` before the function returns.

### D-3: Decrypt reads from stdout only; `{{.OutPath}}` is not substituted

In `decrypt_command`, `{{.OutPath}}` is never substituted. The decrypted plaintext is always captured from the command's stdout. This means no plaintext file is written to disk by the tool — only a ciphertext temp file is created (for the `{{.InPath}}` case).

If an operator writes `{{.OutPath}}` in `decrypt_command`, the placeholder is left as a literal string in the argv. The command will likely fail; this is intentional and documented — `{{.OutPath}}` is `encrypt_command`-only.

Rationale: writing plaintext to disk, even briefly, expands the attack surface. Capturing stdout keeps the plaintext entirely in process memory.

### D-4: Both commands are required at config parse time

`encrypt_command` and `decrypt_command` are both required in the HCL block. A config missing either is rejected with a parse-time error.

Rationale: a config without `decrypt_command` is valid on a fresh run (only encrypt is called) but silently broken on every subsequent run that needs to sign hosts under an encrypted CA key. Surfacing the error at parse time rather than mid-run is strictly better. The operator who truly does not need decryption should use `encryption "none"`.

### D-5: Mismatch fingerprint is SHA-256 of `encrypt_command`

The `EncryptionRecord.recipients_sha` field stores a SHA-256 hash of the full `encrypt_command` slice (elements joined with a null byte as separator to prevent boundary ambiguity). When this hash changes between runs, the tool prints the same "encrypted with different recipients" warning as the sops backend and directs the operator to `nebula-pki reencrypt`.

Using the whole `encrypt_command` (not just key IDs) as the fingerprint means any change to the encryption logic — even a flag — is detected. This is conservative but correct: the operator knows best when a "same key, different flag" change still produces interoperable ciphertext.

## Positive Consequences

* `{{.InPath}}` and `{{.OutPath}}` are self-documenting in config files; users never mistake them for content.
* Operators with stdin/stdout tools get zero-overhead integration.
* No plaintext ever touches disk in the decrypt path.
* Errors about missing commands surface before any crypto runs.

## Negative Consequences

* Operators who want to use `{{.OutPath}}` in decrypt (e.g. a tool that only writes to a named output file) must wrap their command in a shell one-liner that redirects to stdout: `sh -c "mytool --out /tmp/out {{.InPath}} && cat /tmp/out && rm /tmp/out"`. This is an acceptable workaround for an uncommon case.

## Links

* ADR-003 — encryption strategy (sops backend; mentions the external backend in passing)
* ADR-006 — storage backend extensibility (decided *why* the external backend exists)
