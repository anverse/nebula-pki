# State and artifact layout

## Status

accepted

> **Trust bundles (amended by [ADR-026](./026-trust-bundle-block.md)).** A bundle is emitted only for each declared `trust_bundle` block, at `bundles/<label>.crt` by default; the manifest records them in a `trust_bundles` map keyed by label, and the CA record's `archived` field is removed. The body below reflects this.

## Context

The CLI must produce certificates and a small amount of bookkeeping data. Downstream Terraform projects read these files directly. We need a layout that is stable, predictable, and safe to commit to git. We also need a manifest format that captures enough metadata to support idempotency, per-cert output placement, and consumption by other tooling.

## Decision

### Artifact layout

Artifacts live under paths chosen by the HCL configuration. The defaults — when no explicit paths are given — are:

```
<out_dir>/
  nebula-pki.json     # manifest; renameable via storage.manifest_file
  ca/
    <label>.crt
    <label>.key[.enc]
  bundles/
    <label>.crt       # one per trust_bundle block; path via trust_bundle.path (ADR-026)
  certs/
    <name>.crt
    <name>.key[.enc]
```

`.enc` is appended by the active encryption backend (`none` writes plain `.key`). The suffix is configurable via `storage.encryption.<backend>.output_suffix`.

Every `ca` block must carry a label ([ADR-015](./015-multiple-cas-per-config.md)), so CA cert/key paths are always `ca/<label>.crt` and `ca/<label>.key[.enc]`. `bundles/<label>.crt` holds the concatenation of the CA certs listed in that bundle's `ca_refs`, in that order, and is written only for a declared `trust_bundle` block. Declaring one from the start gives downstream `pki.ca` one stable path before, during, and after a rotation. See [ADR-016](./016-ca-rotation-and-trust-bundles.md) and [ADR-026](./026-trust-bundle-block.md).

### File modes

All artifacts are written atomically (temp file in the target directory, then
`rename` over the target) so an interrupted run never leaves a torn cert, key,
or manifest — see [ADR-013](./013-atomic-artifact-writes.md). They use the same
permissions `nebula-cert` itself uses:

- `.key` and `.key<suffix>` — `0600` (owner read/write only).
- `.crt` and `.png` — `0600` from `nebula-cert`; nebula-pki copies via `os.WriteFile` and preserves the same mode. Downgrading to `0644` is an operator concern after the fact.
- Manifest (`nebula-pki.json`) — `0644`. Contains no secret material.
- Directories (`out/`, `out/ca/`, `out/<output>/`) — `0755`.

Per-cert outputs may specify a destination directory via `cert.output_dir`; cert and key filenames default to `<cert.name>.crt` / `<cert.name>.key`. The filename (or a sub-path within the directory) may be overridden via `cert.out_crt` / `cert.out_key`, which are joined onto `output_dir` when that is set. See [ADR-020](./020-output-dir-per-cert.md) for the full path-resolution rules.

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
  "trust_bundles": {
    "main": {
      "path": "out/bundles/main.crt",
      "ca_fingerprints": ["f2a1c9...", "ab77e0..."],
      "links": [
        { "path": "out/hetzner/main.crt", "target": "../bundles/main.crt" }
      ]
    }
  },
  "cas": {
    "current": {
      "mode": "generate",
      "name": "mesh-2026",
      "fingerprint": "f2a1c9...",
      "curve": "25519",
      "version": 2,
      "default": true,
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
      "not_before": "2026-05-17T12:43:00Z",
      "not_after":  "2027-05-17T12:43:00Z",
      "cert_path":  "out/ca/next.crt",
      "key_path":   "out/ca/next.key.enc"
    }
  },
  "certs": {
    "lh_fra": {
      "name":        "lh-fra",
      "ca":          "current",
      "fingerprint": "9d4be7...",
      "networks":    ["10.42.0.1/16"],
      "groups":      ["lighthouse"],
      "duration":    "26280h",
      "renew_before": "720h",
      "not_before":  "2026-05-17T12:43:00Z",
      "not_after":   "2029-05-16T12:42:59Z",
      "ca_fingerprint": "f2a1c9...",
      "artifacts": [
        { "dir": "out/hetzner", "cert_path": "out/hetzner/lh-fra.crt", "key_path": "out/hetzner/lh-fra.key.enc" }
      ]
    },
    "alice_phone": {
      "name":        "alice-phone",
      "ca":          "current",
      "fingerprint": "71c0a4...",
      "networks":    ["10.42.5.20/16"],
      "in_pub":      true,
      "not_before":  "2026-05-17T12:43:00Z",
      "not_after":   "2027-05-17T12:42:59Z",
      "ca_fingerprint": "f2a1c9...",
      "artifacts": [
        { "cert_path": "out/certs/alice-phone.crt" }
      ]
    }
  }
}
```

The manifest always uses the `cas` map — there is no legacy single-CA `ca` object. Every CA block requires a label ([ADR-015](./015-multiple-cas-per-config.md)), so `cas` is always present and always has at least one entry.

#### Field rules

- `schema_version` — integer. Bumped only when the manifest format changes incompatibly. Currently `1`.
- `generator.nebula_library_version` — the `slackhq/nebula` Go module version pinned at build time. Matches the value reported by `nebula-pki --version`. See [ADR-012](./012-upstream-nebula-coupling.md). Optional in older manifests; written by all current builds.
- `config_path` — path to the HCL config that produced this manifest, relative to the manifest's directory when possible (absolute fallback). Lets future tooling detect "wrong config writing to my manifest" without enforcing it at runtime.
- `cas` — map of CA label → CA record. Always present; always has at least one entry. Each record carries `mode`, `name`, `fingerprint`, `curve`, `version`, `default`, validity window, and paths. A CA declared in the config but listed in no `trust_bundle.ca_refs` keeps its record; the record is dropped when the `ca` block is deleted (its files stay on disk). See [ADR-015](./015-multiple-cas-per-config.md).
- `cas.<label>.default` — `true` for the one CA marked `default = true` in HCL (the signer for certs that omit `cert.ca`); `false` for the rest. At most one record has `true`. Absent in the legacy single-CA `ca` object. This replaces the earlier top-level `default_ca` field. See [ADR-015](./015-multiple-cas-per-config.md).
- `trust_bundles` — map of bundle label → `{ path, ca_fingerprints, links }`, one entry per declared `trust_bundle` block; absent when none is declared. `path` is where the concatenated-PEM bundle was written (relative to the manifest dir when possible). `ca_fingerprints` lists, in `ca_refs` order, the fingerprint of every member CA cert. `links` records the bundle's managed `link_crt` symlinks, same shape as `cas.<label>.links`. Lets downstream tooling verify what each trust set contains without parsing the PEM. See [ADR-016](./016-ca-rotation-and-trust-bundles.md) and [ADR-026](./026-trust-bundle-block.md).
- `cas.<label>.mode` — `"generate"` or `"reference"`.
- `*.fingerprint` (on `ca`, `cas.*`, and `certs.*`) — the certificate's SHA256 fingerprint as lowercase hex, **no prefix**, exactly as `nebula-cert print -path <crt> -json` emits in its `fingerprint` field. This is the SHA256 of the marshalled certificate (a public artifact handed to every node), not of the public key and not of any private material — so it is always safe to commit.
- `certs.*.name` — the cert Common Name. Equal to the cert's HCL label unless `cert.name` overrides it (see [ADR-009](./009-cert-label-vs-cert-name.md)).
- `certs.*.ca` — the label of the CA that signed this cert (the signing CA resolved from `cert.ca`, or the CA marked `default = true`). `certs.*.ca_fingerprint` pins the exact CA cert regardless.
- `certs.*.duration` — the literal value from HCL (e.g. `"8760h"`). **Omitted** when unset (the cert co-expires with its CA). Used for idempotency; `not_after` is the resolved timestamp from the most recent sign.
- `certs.*.renew_before` — the resolved renewal threshold literal (from `cert.renew_before` or the signing CA's `renew_before`). **Omitted** when neither is set. Recorded so the staleness verdict is reproducible. See [ADR-017](./017-cert-renewal-threshold.md).
- `certs.*.in_pub` — `true` when the cert was signed from an externally-supplied public key ([ADR-018](./018-in-pub-air-gapped-signing.md)). **Omitted** when false.
- Optional fields in general — all optional cert and CA record fields are omitted from the JSON when empty (nil slice, empty string, false bool). Required fields are always present. See [ADR-019](./019-manifest-compactness.md) for the full policy. Such a cert has **no** `key_path` in any `artifacts` entry (cert only) and never carries an encryption suffix.
- `certs.*.artifacts` — always exactly one entry. The entry has `cert_path` and, for key-bearing certs, `key_path`; `in_pub` certs omit `key_path`. When `cert.output_dir` is set, the entry's `dir` field records that value. When the cert lives at the default placement or the path was specified entirely via `out_crt` / `out_key` without `output_dir`, `dir` is omitted (the full path is already captured by `cert_path` / `key_path`).
- `encryption` — the resolved sops configuration for the run. Whichever key-type fields were set in HCL (`age`, `pgp`, `kms`, etc.) appear here verbatim; absent fields are omitted. When the run deferred to `.sops.yaml`, this block records only `backend` and `output_suffix` — recipients live in `.sops.yaml`. All values are public and safe to commit.

### Pruning removed certs

When a `cert` block is deleted from HCL but exists in the previous manifest, all of its recorded `artifacts` paths (cert, key, QR if any) are deleted from disk during reconcile. The QR for the cert is deleted alongside the cert/key. The corresponding entry is dropped from the new manifest.

`--dry-run` lists the would-be-deleted paths but does not touch them. Files the tool never recorded are left alone.

### Idempotency rule

A cert is **up to date** when:

1. Its manifest entry exists.
2. All `artifacts` paths exist on disk.
3. Cert fields (`name`, `networks`, `groups`, `unsafe_networks`) on the manifest entry match the HCL spec and the cert on disk.
4. The manifest's recorded `duration` literal matches the HCL `duration` literal (or both are unset, meaning "CA expiry minus 1s").
5. `not_after` is still in the future.
6. `ca_fingerprint` matches the cert's currently-resolved signing CA (so moving the `default = true` marker, or changing a `cert.ca`, during a rotation triggers a re-sign — see [ADR-016](./016-ca-rotation-and-trust-bundles.md)).
7. The cert is **not** within its effective `renew_before` window of `not_after` — i.e. `now + renew_before < not_after`. When no `renew_before` resolves, this clause is vacuously satisfied (no time-based renewal). See [ADR-017](./017-cert-renewal-threshold.md).

Otherwise the cert is re-signed. The manifest records the **literal** `duration` value from HCL (e.g. `"8760h"`), not the resolved `not_after`. This keeps re-runs idempotent: `not_after` shifts forward on every sign, but identical inputs produce the same up-to-date verdict.

For `in_pub` certs ([ADR-018](./018-in-pub-air-gapped-signing.md)) the same rules apply except there is no key artifact to check or write: a re-sign refreshes the cert from the same supplied public key, and clause 2 checks only `cert_path` entries.

Time-based renewal (clause 7) is the one place the up-to-date verdict depends on wall-clock time: a run inside the window re-signs once and pushes `not_after` forward, after which the cert is immediately outside the window again, so there is no churn loop. Outside any window, re-runs remain byte-identical. The injectable clock keeps this deterministic under test. Operators who want an immediate new `not_after` regardless of window bump `duration` (or use `--force`, deferred).

Existing files are not overwritten silently — Nebula refuses to overwrite, so the tool removes its own previously-recorded paths before re-signing.

### CA rules

A generate-mode CA is up to date when its manifest entry exists and its cert and key are on disk; it is generated only when it is neither recorded nor on disk. Half a pair, or a pair on disk the manifest does not record, is an error ([ADR-013](./013-atomic-artifact-writes.md)). A CA is also pinned to its label ([ADR-027](./027-ca-pinned-to-label.md), 2026-10-04/05): a recorded CA whose cert and key are both gone, or whose certificate fingerprint differs from the recorded one (in either mode), is an error rather than a new CA. Clause 6 above compares the signing CA by label in the implementation; with CAs pinned to their labels that is equivalent to comparing `ca_fingerprint`.

## Consequences

- The manifest is the single comparator; no separate state file.
- Per-cert output placement is recorded explicitly so downstream tooling can locate artifacts without inferring paths.
- Multiple CAs and rotation progress are observable from `cas` + `certs.*.ca`; the `trust_bundles` records state exactly what each trust set contains. See [ADR-015](./015-multiple-cas-per-config.md), [ADR-016](./016-ca-rotation-and-trust-bundles.md).
- Reference-mode CA is fully supported: the tool does not touch the existing CA files.
- Renaming a cert counts as remove + add. The old fingerprint is still in the previous git commit if needed for an external blocklist.
- If a user deletes any artifact for a cert, the next run reissues that cert's certificate (and key, unless `in_pub`).
- Manifest is regenerated whenever a run makes changes; partial runs leave the previous manifest intact. A run where every cert and every CA are already up to date, and no cert is inside a renewal window, writes **nothing** — not even the manifest — so an unchanged tree stays byte-identical across re-runs.
