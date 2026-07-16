# Storage backend extensibility

* Status: accepted
* Deciders: fw
* Date: 2026-05-17

## Context and Problem Statement

The tool should be approachable for first-time users (no encryption configured, just generate certs) and powerful for the maintainers' use case (sops + age by default). It should also accommodate operators with existing secret-management tooling without forcing them onto sops. We must decide how extensible the encryption layer should be.

## Decision Drivers

* Easy "out of the box" path for newcomers.
* First-class sops + age support for the primary use case.
* Escape hatch for users with bespoke tooling.
* Minimum implementation and maintenance complexity.
* No requirement (yet) to ship third-party-authored extensions as separate binaries.

## Considered Options

* A. Hard-code sops as the only encryption option.
* B. Built-in backends only (`none`, `sops`), no extensibility.
* C. Built-in backends plus a generic `external` backend that invokes an operator-supplied command.
* D. Full plugin system using HashiCorp `go-plugin` (separate binaries discovered at runtime, like Terraform providers).

## Decision Outcome

Chosen option: **C — built-in `none` and `sops` backends, plus a generic `external` backend.** This satisfies all three audiences (newcomer, maintainer, BYO-tooling) with one Go binary and no plugin discovery machinery.

The backend is selected by a labelled block under `storage`:

```hcl
storage {
  out_dir = "out"

  encryption "sops" {
    age = ["age1..."]
  }
}
```

Other valid labels: `"none"` (default if omitted), `"external"`.

The `external` backend invokes a user-supplied command:

```hcl
encryption "external" {
  encrypt_command = ["my-tool", "encrypt", "--in", "{{.InPath}}", "--out", "{{.OutPath}}"]
  decrypt_command = ["my-tool", "decrypt", "--in", "{{.InPath}}"]
  output_suffix   = ".enc"
}
```

`{{.InPath}}` and `{{.OutPath}}` are substituted with absolute temp-file paths. When absent, input is piped via stdin and output is read from stdout. `{{.OutPath}}` is not substituted in `decrypt_command` — plaintext is always captured from stdout. Both commands are required. See ADR-023 for the full protocol.

Placeholders `{{.In}}` and `{{.Out}}` are substituted with absolute paths to the plaintext source file (which the tool writes to a temp location) and the desired ciphertext destination. The command is expected to exit 0 on success. The tool deletes the plaintext temp file on completion.

### Positive Consequences

* One binary, no plugin runtime, no version-matching dance.
* Newcomers run the tool with no encryption config and get plain files.
* sops + age users get a first-class experience with one block of HCL.
* Any other encryption story (pass, gpg, custom KMS wrapper, ...) is a shell-out away.

### Negative Consequences

* The `external` backend's contract is informal (argv + exit code). Errors from user commands surface as exit-status messages.
* If a real plugin ecosystem emerges later, we will need to migrate to a richer interface. This is deemed acceptable; YAGNI.

## Pros and Cons of the Options

### A. Hard-code sops

* Good, because trivially simple.
* Bad, because it forces all users onto sops + age.
* Bad, because newcomers must learn sops before producing their first cert.

Rejected.

### B. Built-in `none` + `sops` only

* Good, because still simple.
* Bad, because users with bespoke tooling are stuck wrapping the tool externally.

Rejected on grounds of forcing wrapper scripts for a common case.

### C. Built-in `none` + `sops` + `external`

* Good, because covers the three known audiences.
* Good, because the `external` contract is dead simple.
* Bad, because three code paths to maintain.

Accepted.

### D. `go-plugin` based system

* Good, because clean separation, third-party plugins possible.
* Bad, because Terraform-scale machinery for a single-operator tool.
* Bad, because plugin binaries need separate releases, OS/arch matrices, version negotiation.
* Bad, because none of this is justified by current needs.

Rejected as YAGNI. Reconsider only if a real third-party plugin appears.

## Links

* ADR-003 — encryption strategy (decides sops + age as the recommended backend).
* ADR-005 — HCL schema decision (labelled block pattern matches Terraform conventions).
