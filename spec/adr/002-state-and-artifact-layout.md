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
    bundle.crt        # concatenated PEM of active CA certs; renameable via storage.trust_bundle_file
  hosts/
    <name>.crt
    <name>.key[.enc]
```

`.enc` is appended by the active encryption backend (`none` writes plain `.key`). The suffix is configurable via `storage.encryption.<backend>.output_suffix`.

With multiple labelled CAs ([ADR-015](./015-multiple-cas-per-config.md)), the default CA cert/key paths are `ca/<label>.crt` and `ca/<label>.key[.enc]`; `bundle.crt` still holds the concatenation of every active (non-`archived`) CA cert. The trust bundle is always written — with a single CA it is a one-cert file equal to `ca.crt` — so downstream `pki.ca` has one stable path before, during, and after a rotation. See [ADR-016](./016-ca-rotation-and-trust-bundles.md).

### File modes

All artifacts are written atomically (temp file in the target directory, then
`rename` over the target) so an interrupted run never leaves a torn cert, key,
or manifest — see [ADR-013](./013-atomic-artifact-writes.md). They use the same
permissions `nebula-cert` itself uses:

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
  "trust_bundle": {
    "path": "out/ca/bundle.crt",
    "ca_fingerprints": ["f2a1c9...", "ab77e0..."]
  },
  "cas": {
    "current": {
      "mode": "generate",
      "name": "mesh-2026",
      "fingerprint": "f2a1c9...",
      "curve": "25519",
      "version": 2,
      "default": true,
      "archived": false,
      "not_before": "2026-05-17T12:43:00Z",
      "not_after":  "2027-05-17T12:43:00Z",
      "cert_path":  "out/ca/current.crt",
      "key_path":   "out/ca/current.key.enc"
    },
    "next": {
      "mode": "generate",
      "name": "mesh-2027",
      "fingerprint": "ab77e0...",
      "curve": "25519",
      "version": 2,
      "default": false,
      "archived": false,
      "not_before": "2026-05-17T12:43:00Z",
      "not_after":  "2027-05-17T12:43:00Z",
      "cert_path":  "out/ca/next.crt",
      "key_path":   "out/ca/next.key.enc"
    }
  },
  "hosts": {
    "lh_fra": {
      "name":        "lh-fra",
      "ca":          "current",
      "fingerprint": "9d4be7...",
      "networks":    ["10.42.0.1/16"],
      "groups":      ["lighthouse"],
      "unsafe_networks": [],
      "duration":    "26280h",
      "renew_before": "720h",
      "in_pub":      false,
      "not_before":  "2026-05-17T12:43:00Z",
      "not_after":   "2029-05-16T12:42:59Z",
      "ca_fingerprint": "f2a1c9...",
      "artifacts": [
        { "dir": "out/hetzner", "cert_path": "out/hetzner/lh-fra.crt", "key_path": "out/hetzner/lh-fra.key.enc" },
        { "dir": "out/shared",  "cert_path": "out/shared/lh-fra.crt",  "key_path": "out/shared/lh-fra.key.enc" }
      ]
    },
    "alice_phone": {
      "name":        "alice-phone",
      "ca":          "current",
      "fingerprint": "71c0a4...",
      "networks":    ["10.42.5.20/16"],
      "groups":      ["mobile"],
      "unsafe_networks": [],
      "duration":    null,
      "in_pub":      true,
      "not_before":  "2026-05-17T12:43:00Z",
      "not_after":   "2027-05-17T12:42:59Z",
      "ca_fingerprint": "f2a1c9...",
      "artifacts": [
        { "dir": "out/hosts", "cert_path": "out/hosts/alice-phone.crt" }
      ]
    }
  }
}
```

For a single unlabelled CA, the manifest retains the legacy top-level `ca` object (the shape shown in earlier releases) instead of `cas`, for back-compat; `cas` is omitted, and no `default` marker appears (a lone CA is implicitly the signer). Tooling should read `cas` when present and fall back to `ca` otherwise. See [ADR-015](./015-multiple-cas-per-config.md).

#### Field rules

- `schema_version` — integer. Bumped only when the manifest format changes incompatibly. Currently `1`.
- `generator.nebula_library_version` — the `slackhq/nebula` Go module version pinned at build time. Matches the value reported by `nebula-pki --version`. See [ADR-012](./012-upstream-nebula-coupling.md). Optional in older manifests; written by all current builds.
- `config_path` — path to the HCL config that produced this manifest, relative to the manifest's directory when possible (absolute fallback). Lets future tooling detect "wrong config writing to my manifest" without enforcing it at runtime.
- `cas` — map of CA label → CA record, present when the config uses labelled CAs ([ADR-015](./015-multiple-cas-per-config.md)). Each record carries `mode`, `name`, `fingerprint`, `curve`, `version`, `default`, `archived`, validity window, and paths. For a single unlabelled CA, the legacy top-level `ca` object is written instead (same record shape, without `default`/`archived`). Exactly one of `ca` / `cas` is present.
- `cas.<label>.default` — `true` for the one CA marked `default = true` in HCL (the signer for hosts that omit `host.ca`); `false` for the rest. At most one record has `true`. Absent in the legacy single-CA `ca` object. This replaces the earlier top-level `default_ca` field. See [ADR-015](./015-multiple-cas-per-config.md).
- `trust_bundle` — `{ path, ca_fingerprints }`. `path` is where the concatenated-PEM bundle was written (relative to the manifest dir when possible). `ca_fingerprints` lists, in bundle order, the fingerprint of every active (non-`archived`) CA cert included. Lets downstream tooling verify what the mesh currently trusts without parsing the PEM. See [ADR-016](./016-ca-rotation-and-trust-bundles.md).
- `cas.<label>.archived` / `ca` — `archived` is `true` when the CA is excluded from the trust bundle and barred from signing. The CA's record is retained either way (archiving never deletes history). The legacy single-CA `ca` object never carries `archived` (a lone CA is always active).
- `ca.mode` / `cas.<label>.mode` — `"generate"` or `"reference"`.
- `*.fingerprint` (on `ca`, `cas.*`, and `hosts.*`) — the certificate's SHA256 fingerprint as lowercase hex, **no prefix**, exactly as `nebula-cert print -path <crt> -json` emits in its `fingerprint` field. This is the SHA256 of the marshalled certificate (a public artifact handed to every host), not of the public key and not of any private material — so it is always safe to commit.
- `hosts.*.name` — the cert Common Name. Equal to the host's HCL label unless `host.name` overrides it (see [ADR-009](./009-host-identifier-vs-cert-name.md)).
- `hosts.*.ca` — the label of the CA that signed this host (the signing CA resolved from `host.ca`, or the CA marked `default = true`). Present with labelled CAs; omitted in the single-CA legacy shape. `hosts.*.ca_fingerprint` pins the exact CA cert regardless.
- `hosts.*.duration` — the literal value from HCL (e.g. `"8760h"`), or `null` when unset. Used for idempotency; `not_after` is the resolved timestamp from the most recent sign.
- `hosts.*.renew_before` — the resolved renewal threshold literal (from `host.renew_before` or the signing CA's `renew_before`), or omitted when neither is set. Recorded so the staleness verdict is reproducible. See [ADR-017](./017-host-renewal-threshold.md).
- `hosts.*.in_pub` — `true` when the host was signed from an externally-supplied public key ([ADR-018](./018-in-pub-air-gapped-signing.md)). Such a host has **no** `key_path` in any `artifacts` entry (cert only) and never carries an encryption suffix.
- `hosts.*.artifacts` — at least one entry. Each entry has `cert_path` and, for key-bearing hosts, `key_path`; `in_pub` hosts omit `key_path`. When the entry came from `host.output_dirs`, the entry's `dir` field is the corresponding directory. When the entry came from the default placement, `dir` is `<storage.out_dir>/hosts`. When the entry came from `host.out_crt` / `host.out_key`, the `dir` field is omitted because the operator chose the paths verbatim.
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
6. `ca_fingerprint` matches the host's currently-resolved signing CA (so moving the `default = true` marker, or changing a `host.ca`, during a rotation triggers a re-sign — see [ADR-016](./016-ca-rotation-and-trust-bundles.md)).
7. The host is **not** within its effective `renew_before` window of `not_after` — i.e. `now + renew_before < not_after`. When no `renew_before` resolves, this clause is vacuously satisfied (no time-based renewal). See [ADR-017](./017-host-renewal-threshold.md).

Otherwise the host is re-signed. The manifest records the **literal** `duration` value from HCL (e.g. `"8760h"`), not the resolved `not_after`. This keeps re-runs idempotent: `not_after` shifts forward on every sign, but identical inputs produce the same up-to-date verdict.

For `in_pub` hosts ([ADR-018](./018-in-pub-air-gapped-signing.md)) the same rules apply except there is no key artifact to check or write: a re-sign refreshes the cert from the same supplied public key, and clause 2 checks only `cert_path` entries.

Time-based renewal (clause 7) is the one place the up-to-date verdict depends on wall-clock time: a run inside the window re-signs once and pushes `not_after` forward, after which the host is immediately outside the window again, so there is no churn loop. Outside any window, re-runs remain byte-identical. The injectable clock keeps this deterministic under test. Operators who want an immediate new `not_after` regardless of window bump `duration` (or use `--force`, deferred).

Existing files are not overwritten silently — Nebula refuses to overwrite, so the tool removes its own previously-recorded paths before re-signing.

## Consequences

- The manifest is the single comparator; no separate state file.
- Multi-output fan-out is recorded explicitly per host, so downstream tooling can pick a specific output without inferring paths.
- Multiple CAs and rotation progress are observable from `cas` + `hosts.*.ca`; the emitted `trust_bundle` records exactly what the mesh trusts. See [ADR-015](./015-multiple-cas-per-config.md), [ADR-016](./016-ca-rotation-and-trust-bundles.md).
- Reference-mode CA is fully supported: the tool does not touch the existing CA files.
- Renaming a host counts as remove + add. The old fingerprint is still in the previous git commit if needed for an external blocklist.
- If a user deletes any artifact for a host, the next run reissues that host's certificate (and key, unless `in_pub`).
- Manifest is regenerated whenever a run makes changes; partial runs leave the previous manifest intact. A run where every host and every CA are already up to date, and no host is inside a renewal window, writes **nothing** — not even the manifest — so an unchanged tree stays byte-identical across re-runs.
