# nebula-pki

**See your entire Nebula mesh on one screen.** Add a host with three lines. Review cert changes the same way you review code. Re-run the tool and get the same result every time.

`nebula-pki` is a declarative layer over [`nebula-cert`](https://github.com/slackhq/nebula): you describe the mesh once in HCL, the tool keeps the on-disk certificates in sync.

> nebula-pki is under active development. It's ready to use day-to-day and we aim to keep the schema stable, but breaking changes may still happen before v1.0.

## What you get

- **One config, whole mesh.** CA and every host in a single HCL. With `nebula-cert` you'd reconstruct that picture from shell history.
- **Reviewable.** Cert changes flow through pull requests like any other code.
- **Reproducible.** Same config in, same artifacts out. `nebula-cert` produces whatever you remembered to type that day.
- **Multiple output directories.** One host's cert can land in several directories in a single run. No more shell loops copying files around.
- **No flag juggling.** Each host's networks, groups, and duration sit next to its name. No more re-typing the right `-networks`, `-groups`, `-duration` combo per host.

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
go install github.com/anverse/nebula-pki@latest
```

### From source

```sh
git clone https://github.com/anverse/nebula-pki
cd nebula-pki
go build -o nebula-pki ./cmd/nebula-pki
```

The binary is self-contained. It links the `slackhq/nebula/cert` Go library directly, so you don't need to install Nebula or `nebula-cert` alongside it.
Each release pins one upstream Nebula version (visible in release notes, `nebula-pki --version`, and the manifest).
The built-in sops backend uses the sops Go library — no external `sops` CLI required.

## Quickstart

`nebula.hcl`:

```hcl
ca {
  name     = "my-mesh"
  duration = "8760h"
}

host "lh_01" {
  networks = ["10.42.0.1/16"]
  groups   = ["lighthouse"]
}

host "app_01" {
  networks = ["10.42.1.10/16"]
  groups   = ["app"]
}
```

```sh
nebula-pki
```

That's it. Running the tool reconciles `out/` with `nebula.hcl` — generates the CA if it doesn't exist, signs missing host certs, and updates the manifest at `out/nebula-pki.json`.

Need certificates split across multiple Terraform projects? See **Per-host output directory** below.

## Per-host output directory

Running a mesh that spans several Terraform projects, providers, or deploy targets? Each one usually only needs the certs for the hosts it owns. `output_dir` places a host's cert and key in a specific directory so every downstream project reads from its own folder and sees nothing else.

```hcl
host "lh_fra" {
  name       = "lh-fra"          # cert CN; optional, defaults to label
  networks   = ["10.42.0.1/16"]
  output_dir = "out/hetzner"     # cert written to out/hetzner/lh-fra.{crt,key}
}

host "app_hetzner_01" {
  networks   = ["10.42.1.10/16"]
  output_dir = "out/hetzner"
}
```

Filenames default to `<host.name>.crt` / `.key`. Use `out_crt` / `out_key` to rename them while keeping the same `output_dir`:

```hcl
host "lh_fra" {
  networks   = ["10.42.0.1/16"]
  output_dir = "out/hetzner"
  out_crt    = "nebula.crt"      # → out/hetzner/nebula.crt
}
```

## Encryption (coming soon, opt-in)

By default, host keys land on disk as plaintext, which means you can't safely keep `out/` in git. The optional encryption wrapper fixes that: keys are encrypted at rest using sops (built-in, no extra CLI needed) with whatever recipients your `.sops.yaml` already defines — age, PGP, KMS, Vault. Commit the whole `out/` directory without leaking secrets; the manifest itself holds none.

```hcl
storage {
  encryption "sops" {
    age = ["age1abc...", "age1def..."]
  }
}
```

Every `.key` gets the configured suffix (default `.enc`). Decrypt with the regular `sops` CLI when needed.

The block behaves like the `sops` CLI itself: every field maps to a sops flag, and an **empty** `encryption "sops" {}` defers entirely to your existing `.sops.yaml` (age, PGP, KMS, Vault — whatever you already use). See [`agents.md`](./agents.md) for the full field list and the `external` backend.

## CLI

```sh
nebula-pki                # reconcile out/ with nebula.hcl  (default action)
nebula-pki --dry-run      # preview what would change; no writes
nebula-pki check          # parse and validate nebula.hcl; no I/O against out/
nebula-pki -c other.hcl   # use a different config path
```

That's the whole surface. No subcommands to memorise for the everyday workflow.

## Consuming from Terraform

```hcl
resource "some_provider_file" "nebula_cert" {
  content = file("${path.module}/../nebula/out/hetzner/app_hetzner_01.crt")
}
```

Encrypted key files (suffix configurable, `.enc` by default) can be read by the [`carlpett/sops`](https://registry.terraform.io/providers/carlpett/sops/latest) Terraform provider, or by the target host's own bootstrap tooling.

## Want more?

- Full HCL reference, encryption backends, CA reference mode, host options: [`agents.md`](./agents.md).
- Building, testing, releasing: [`development.md`](./development.md).
- Design rationale and decisions: [`spec/`](./spec/readme.md).
- Upstream Nebula: <https://github.com/slackhq/nebula>.

---

_Copyright (c) 2026 The nebula-pki Authors. Licensed under the MIT License — see [`LICENSE`](./LICENSE)._
