# nebula-pki

**See your entire Nebula mesh on one screen.** Add a host with three lines. Review cert changes the same way you review code. Re-run the tool and get the same result every time.

`nebula-pki` is a declarative layer over [`nebula-cert`](https://github.com/slackhq/nebula): you describe the mesh once in HCL, the tool keeps the on-disk certificates in sync.

## Why use it

- **Clarity.** Your CA and every host's identity live in one file you can read top-to-bottom. No more grep-ing through shell scripts to find which cert went where.
- **Less toil.** Onboarding a new host is a 3-line HCL edit, not a sequence of remembered commands. Removing one is deleting a block. Renewals are a single re-run.
- **Reviewable changes.** Cert and CA edits go through the same pull-request flow as everything else. The diff *is* the change request.
- **Reproducible.** Same config in, same artifacts out. Onboarding a colleague is `git clone` and run.
- **Thin and honest.** Every HCL field maps to a real `nebula-cert` flag. No magic, no lock-in — drop the tool and your certs keep working.
- **Safe to commit.** Want to keep your `out/` directory in git? Turn on the optional encryption wrapper: keys get encrypted on disk via sops (built-in, no extra CLI to install) using whatever key type your `.sops.yaml` already declares — age, PGP, KMS, Vault, all supported — or use any encrypt command you prefer. The manifest itself holds zero secrets either way.

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

The binary is self-contained. The built-in sops backend uses the sops Go library — no external `sops` CLI required.

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

Need certificates split across multiple Terraform projects? See **Fan-out** below.

## Fan-out: the killer feature

```hcl
host "lh_fra" {
  name        = "lh-fra"                              # cert CN; optional, defaults to label
  networks    = ["10.42.0.1/16"]
  output_dirs = ["out/hetzner", "out/aws"]            # cert written to BOTH dirs
}

host "app_hetzner_01" {
  networks    = ["10.42.1.10/16"]
  output_dirs = ["out/hetzner"]
}
```

Each downstream Terraform project reads from its provider's directory and never sees hosts that don't concern it. `output_dirs` accepts directories only — filenames are always `<host.name>.crt` / `.key`.

## Encryption (opt-in)

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
