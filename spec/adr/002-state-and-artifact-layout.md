# State and artifact layout

## Status

accepted

## Context

The CLI must produce certificates and a small amount of bookkeeping data. Downstream Terraform projects read these files directly. We need a layout that is stable, predictable, and safe to commit to git. We also need a manifest format that captures enough metadata to support idempotency, multi-output fan-out, and consumption by other tooling.

## Decision

### Artifact layout

Artifacts live under paths chosen by the HCL configuration. The defaults — when no explicit paths are given — are:

```
<out_dir>/
  nebula-pki.json     # manifest; renameable via storage.manifest_file
  ca/
    ca.crt
    ca.key[.enc]
  hosts/
    <name>.crt
    <name>.key[.enc]
```

`.enc` is appended by the active encryption backend (`none` writes plain `.key`). The suffix is configurable via `storage.encryption.<backend>.output_suffix`.

### File modes

All artifacts are written with the same permissions `nebula-cert` itself uses:

- `.key` and `.key<suffix>` — `0600` (owner read/write only).
- `.crt` and `.png` — `0600` from `nebula-cert`; nebula-pki copies via `os.WriteFile` and preserves the same mode. Downgrading to `0644` is an operator concern after the fact.
- Manifest (`nebula-pki.json`) — `0644`. Contains no secret material.
- Directories (`out/`, `out/ca/`, `out/<output>/`) — `0755`.

Per-host outputs may override defaults via `host.out_crt` / `host.out_key`, or via `host.output_dirs`. When a host lists multiple directories in `output_dirs`, identical copies of its cert and key are written to each.

In **reference mode** for the CA (the user supplies pre-existing `ca.crt` / `ca.key` paths), the tool reads those files in place and does **not** write anything under `ca/`. The manifest still records the CA's fingerprint and validity window.

### Manifest

The manifest is the tool's source of truth for idempotency and is committed to git. It contains **no secret material**.

Default filename is `nebula-pki.json`, written at `<storage.out_dir>/nebula-pki.json`. The path is configurable via `storage.manifest_file`, which is useful when multiple `*.hcl` configurations share a working directory (e.g. `dev.hcl` + `prod.hcl`). Relative paths resolve against the config file's directory; absolute paths are honoured as-is.

#### Schema (informal)

```json
{
  "schema_version": 1,
  "generated_at": "2026-05-17T12:43:00Z",
  "generator": { "name": "nebula-pki", "version": "0.1.0", "nebula_library_version": "v1.9.5" },
  "config_path": "nebula.hcl",
  "encryption": {
    "label": "sops",
    "age": ["age1xyz..."],
    "output_suffix": ".enc"
  },
  "ca": {
    "mode": "generate",
    "name": "wiech-mesh",
    "fingerprint": "sha256:abc...",
    "curve": "25519",
    "version": 2,
    "not_before": "2026-05-17T12:43:00Z",
    "not_after":  "2029-05-16T12:43:00Z",
    "cert_path":  "out/ca/ca.crt",
    "key_path":   "out/ca/ca.key.enc"
  },
  "hosts": {
    "lh_fra": {
      "name":        "lh-fra",
      "fingerprint": "sha256:def...",
      "networks":    ["10.42.0.1/16"],
      "groups":      ["lighthouse"],
      "unsafe_networks": [],
      "duration":    "26280h",
      "not_before":  "2026-05-17T12:43:00Z",
      "not_after":   "2029-05-16T12:42:59Z",
      "ca_fingerprint": "sha256:abc...",
      "artifacts": [
        { "dir": "out/hetzner", "cert_path": "out/hetzner/lh-fra.crt", "key_path": "out/hetzner/lh-fra.key.enc" },
        { "dir": "out/shared",  "cert_path": "out/shared/lh-fra.crt",  "key_path": "out/shared/lh-fra.key.enc" }
      ]
    }
  }
}
```

#### Field rules

- `schema_version` — integer. Bumped only when the manifest format changes incompatibly. Currently `1`.
- `generator.nebula_library_version` — the `slackhq/nebula` Go module version pinned at build time. Matches the value reported by `nebula-pki --version`. See [ADR-012](./012-upstream-nebula-coupling.md). Optional in older manifests; written by all current builds.
- `config_path` — path to the HCL config that produced this manifest, relative to the manifest's directory when possible (absolute fallback). Lets future tooling detect "wrong config writing to my manifest" without enforcing it at runtime.
- `ca.mode` — `"generate"` or `"reference"`.
- `ca.fingerprint` and `hosts.*.fingerprint` — SHA256 hex of the public key, formatted as `sha256:<hex>`. Matches what `nebula-cert print -path <crt> -json` emits in the `fingerprint` field.
- `hosts.*.name` — the cert Common Name. Equal to the host's HCL label unless `host.name` overrides it (see [ADR-009](./009-host-identifier-vs-cert-name.md)).
- `hosts.*.duration` — the literal value from HCL (e.g. `"8760h"`), or `null` when unset. Used for idempotency; `not_after` is the resolved timestamp from the most recent sign.
- `hosts.*.artifacts` — at least one entry. Each entry has `cert_path` and `key_path`. When the entry came from `host.output_dirs`, the entry's `dir` field is the corresponding directory. When the entry came from the default placement, `dir` is `<storage.out_dir>/hosts`. When the entry came from `host.out_crt` / `host.out_key`, the `dir` field is omitted because the operator chose the paths verbatim.
- `encryption` — the resolved sops configuration for the run. Whichever key-type fields were set in HCL (`age`, `pgp`, `kms`, etc.) appear here verbatim; absent fields are omitted. When the run deferred to `.sops.yaml`, this block records only `backend` and `output_suffix` — recipients live in `.sops.yaml`. All values are public and safe to commit.

### Pruning removed hosts

When a `host` block is deleted from HCL but exists in the previous manifest, all of its recorded `artifacts` paths (cert, key, QR if any) are deleted from disk during reconcile. The QR for the host is deleted alongside the cert/key. The corresponding entry is dropped from the new manifest.

`--dry-run` lists the would-be-deleted paths but does not touch them. Files the tool never recorded are left alone.

### Idempotency rule

A host is **up to date** when:

1. Its manifest entry exists.
2. All `artifacts` paths exist on disk.
3. Cert fields (`name`, `networks`, `groups`, `unsafe_networks`) on the manifest entry match the HCL spec and the cert on disk.
4. The manifest's recorded `duration` literal matches the HCL `duration` literal (or both are unset, meaning "CA expiry minus 1s").
5. `not_after` is still in the future.
6. `ca_fingerprint` matches the currently active CA.

Otherwise the host is re-signed. The manifest records the **literal** `duration` value from HCL (e.g. `"8760h"`), not the resolved `not_after`. This keeps re-runs idempotent: `not_after` shifts forward on every sign, but identical inputs produce the same up-to-date verdict.

Renewal-before-expiry is not automatic in v1. Operators bump `duration` (or run with `--force`, deferred) when they want a new `not_after`. A future ADR may add a renewal threshold.

Existing files are not overwritten silently — Nebula refuses to overwrite, so the tool removes its own previously-recorded paths before re-signing.

## Consequences

- The manifest is the single comparator; no separate state file.
- Multi-output fan-out is recorded explicitly per host, so downstream tooling can pick a specific output without inferring paths.
- Reference-mode CA is fully supported: the tool does not touch the existing CA files.
- Renaming a host counts as remove + add. The old fingerprint is still in the previous git commit if needed for an external blocklist.
- If a user deletes any artifact for a host, the next run reissues that host's certificate and key.
- Manifest is regenerated on every successful run; partial runs leave the previous manifest intact.
