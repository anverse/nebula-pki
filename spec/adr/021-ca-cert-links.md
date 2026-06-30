# CA cert symlink fan-out (`link_crt`)

* Status: accepted
* Deciders: fw
* Date: 2026-06-30

## Context and Problem Statement

Each Nebula host needs three files to run: `host.key`, `host.crt`, and `ca.crt` (the trust bundle or the specific CA cert). When hosts are fanned out to per-provider directories via `host.output_dir`, the host key and cert land there automatically. The CA cert does not — it lives under `<storage.out_dir>/ca/`. Operators currently copy or manually symlink it into each host directory.

This is error-prone and must be repeated whenever a new output directory is introduced. The tool should manage these links declaratively so they are created, kept correct, and cleaned up without manual intervention.

## Decision Drivers

* Symlinks committed to git must survive `git clone` to any path on any machine.
* The feature should reuse existing path-resolution conventions rather than introducing a new naming system.
* The tool must never silently clobber non-symlink files.
* Idempotency: a re-run verifies existing links rather than always recreating them.
* Explicit over magic: the operator declares which directories need the CA cert; the tool does not auto-infer this from `host.output_dir` values.

## Decision

### Field placement and semantics

Add `link_crt = [...]` as a `list(string)` attribute on the `ca` block. Each entry is a **directory path**. The tool creates one symlink per entry, placing it in the listed directory.

```hcl
ca "mesh" {
  name     = "mesh-2026"
  duration = "8760h"
  link_crt = ["out/hetzner", "out/aws"]
}
```

### Symlink filename

The symlink filename within each listed directory follows the same logic as the CA cert filename:

- Default: `<label>.crt` (same as the CA cert written to `<out_dir>/ca/<label>.crt`).
- When `out_crt` is set on the `ca` block: the basename of the resolved `out_crt` path.

This reuses the existing label/`out_crt` path-resolution convention and means the link and the cert it points to always share the same filename — operators reference one name across all locations.

Example with explicit `out_crt`:

```hcl
ca "mesh" {
  out_crt  = "out/ca/ca.crt"          # CA cert written as ca.crt
  link_crt = ["out/hetzner", "out/aws"]
}
# creates: out/hetzner/ca.crt → ../../ca/ca.crt
#          out/aws/ca.crt     → ../../ca/ca.crt
```

### Relative symlink targets

Symlink targets are always computed as relative paths using `filepath.Rel(linkDir, caAbsCertPath)`. Absolute symlinks are not supported.

**Why relative?** When a symlink is committed to git, git stores the target string verbatim. An absolute target (`/Users/fw/Projects/.../ca/mesh.crt`) is tied to one machine's filesystem layout; it breaks on any other clone or CI agent. A relative target (`../../ca/mesh.crt`) is invariant under `git clone` as long as the directory structure within the repository is preserved — which is exactly what git guarantees when you commit both the symlink and the CA cert.

An `--abs-links` flag is intentionally absent. If the two paths are on different filesystems and `filepath.Rel` cannot produce a valid relative path, the tool errors with a clear message; in that unusual situation the operator creates the symlink manually outside the tool's scope.

### Directory creation

If a listed directory does not exist at reconcile time, the tool creates it (consistent with how `apply` handles `output_dir` for host artifacts).

### Idempotency

For each declared link, the planner:

1. Calls `os.Lstat(linkPath)` — distinguishes symlinks from regular files without following the target.
2. If absent → emit `CreateSymlink`.
3. If present and is a symlink:
   - Read target via `os.Readlink`.
   - If target matches computed relative path → `Noop`.
   - If target differs → emit `CreateSymlink` (recreates; old symlink replaced atomically via `os.Remove` + `os.Symlink`).
4. If present and is **not** a symlink (regular file, directory) → error: the tool refuses to clobber it.

### Stale link cleanup

The manifest records every managed link. On each run the planner diffs the manifest's `cas.<label>.links` against the declared `link_crt` list:

- A path present in the manifest but absent from the config → emit `DeleteSymlink`.
- `DeleteSymlink` in `apply`: re-checks with `os.Lstat`; if it is a symlink, calls `os.Remove`; if it is now a regular file, prints a notice and skips — consistent with the policy of never auto-deleting non-symlink files.

### Manifest representation

```json
{
  "cas": {
    "mesh": {
      "links": [
        {"path": "out/hetzner/mesh.crt", "target": "../../ca/mesh.crt"},
        {"path": "out/aws/mesh.crt",     "target": "../../ca/mesh.crt"}
      ]
    }
  }
}
```

`path` is the symlink's path (relative to the config file's directory); `target` is the relative string stored in the symlink, as returned by `os.Readlink`.

## Interaction with `output_dir`

The primary use case is pairing `link_crt` directories with `host.output_dir` values:

```hcl
ca "mesh" {
  name     = "mesh-2026"
  duration = "8760h"
  link_crt = ["out/hetzner", "out/aws"]   # mirrors the output_dir values below
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

The tool does **not** auto-populate `link_crt` from declared `output_dir` values. The operator lists them explicitly. This is intentional: the CA may serve hosts across many directories, and not every host directory needs the CA cert co-located (some downstream systems point at a central cert path). Automation here would be magic with non-obvious scope; explicit declaration is unambiguous.

`spec/hcl-schema.md` should include a worked example pairing `link_crt` with `output_dir` to guide operators toward the pattern.

## Consequences

### Positive

- CA cert co-location is declarative, version-controlled, and managed by the same reconcile loop that manages certs.
- Symlinks committed to git survive clone to any path.
- No operator-managed copy scripts; stale links are detected and cleaned up automatically.
- Reuses existing filename-derivation logic; no new naming conventions.

### Negative

- Operators must keep `link_crt` in sync with their `output_dir` values manually. A documentation example mitigates this.
- Cross-filesystem setups (rare for a git-backed PKI) cannot use this feature.

## Links

- [ADR-020](./020-output-dir-per-host.md) — per-host `output_dir`; motivation for the fan-out pattern.
- [ADR-002](./002-state-and-artifact-layout.md) — artifact layout and manifest schema.
- [Milestone v0.2](../milestones/v0.2.md) — feature context and iteration plan.
