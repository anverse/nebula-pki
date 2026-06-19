# Per-host output directory: single `output_dir`, composable `out_crt` / `out_key`

## Status

accepted; supersedes [ADR-011](./011-output-blocks-are-directories.md)

## Context

ADR-011 established `host.output_dirs` as a `list(string)` to write identical cert/key copies to multiple destination directories — a "fan-out" pattern. The motivating use case was: one host cert deployed to several provider directories in a single run.

After evaluating real operator workflows, the core need is simpler: **put this host's cert in a specific directory** rather than the default `<storage.out_dir>/hosts`. Multi-directory fan-out was never validated by an actual use case and introduced implementation complexity disproportionate to its value:

- Idempotency requires checking every artifact path on every run.
- Adding a directory to the list triggers a full re-sign (new key material), which is surprising for what feels like a deployment change, not a signing change.
- Removing a directory causes the manifest to describe a superset of what the current config targets, with no clean remediation.
- The natural fix for the re-sign problem ("copy the existing cert to the new directory instead of signing") requires cert validity checking that belongs in the renewal subsystem (v0.0.10), not here.

The existing `out_crt` / `out_key` escape hatch accepted full paths (directory + filename). When cert and key share a directory — which is always the common case — the directory had to be written twice. That is awkward and error-prone.

## Decision

Replace `host.output_dirs` (a `list(string)`) with a single `host.output_dir` (a string) and redefine `out_crt` / `out_key` as composable path components rather than full-path overrides.

### Fields

**`host.output_dir`** — optional destination directory for this host's cert and key. Relative paths resolve against the config file's directory; absolute paths are honoured.

**`host.out_crt`** / **`host.out_key`** — path components. When `output_dir` is set, each is joined onto it. When `output_dir` is absent, each is resolved directly relative to the config file. A bare filename (`nebula.crt`) and a relative sub-path (`certs/nebula.crt`) are both valid; the two fields are independent and may each carry different sub-paths within the same base directory.

### Path resolution

```
base      = output_dir            if set
            else <storage.out_dir>/hosts

cert_path = Join(base, out_crt)   if out_crt set
            else Join(base, <host.name>.crt)

key_path  = Join(base, out_key)   if out_key set
            else Join(base, <host.name>.key)
```

`filepath.Join` is used throughout: it concatenates and cleans. There is no special treatment for path separators inside `out_crt` / `out_key` — relative sub-paths work naturally (`Join("deploy", "certs/node.crt")` → `"deploy/certs/node.crt"`). If the final cert or key path needs to be absolute, make `output_dir` absolute and leave `out_crt` / `out_key` as bare filenames; combining an absolute `out_crt` with a set `output_dir` will produce a joined path, not an override, which is probably not what was intended.

### Mutual exclusivity removed

`output_dir` and `out_crt` / `out_key` are no longer mutually exclusive — they compose. The previous validation rule that forbade `out_crt`/`out_key` alongside `output_dirs` is removed.

### Re-sign on path change

When any of `output_dir`, `out_crt`, or `out_key` changes between runs, the resolved path differs from the manifest's recorded `artifacts` entry. Because the new path's files are absent, the planner emits `OpSign`. The host is re-signed at the new location and the manifest is updated.

After signing, if the old manifest artifact path differs from the newly resolved one and the old file still exists on disk, the CLI prints a notice identifying the old path as no longer managed and suggesting manual deletion. The tool never auto-deletes cert or key files.

### Multi-directory fan-out deferred

Distributing the same cert to multiple directories simultaneously is deferred to a future version. The bar for reintroducing it is per-destination metadata that has no good home on the host itself — per-destination encryption recipients, file modes, or post-write hooks — the same trigger conditions ADR-011 identified. Until then, operators who need N copies run the tool N times with different configs, or copy the artifact themselves after the run.

## Consequences

### Positive

- Directory and filename are specified independently; writing the directory twice when cert and key share a location is no longer required.
- The schema surface shrinks: one field for the common case (`output_dir`), two for filename customisation (`out_crt` / `out_key`), all composable.
- Exactly one artifact per host — idempotency checks are a single file existence test rather than a loop.
- The "adding a directory triggers a surprise re-sign" behaviour from fan-out is gone.

### Negative

- Operators who relied on `output_dirs = ["dir-a", "dir-b"]` for true simultaneous fan-out must use two config files or copy artifacts themselves.
- Changing `output_dir` (or `out_crt` / `out_key`) re-signs the host. The stale-file notice tells the operator what to clean up; the old cert remains on disk until deleted.

## Links

- [ADR-011](./011-output-blocks-are-directories.md) — superseded; established `output_dirs` as a list.
- [ADR-002](./002-state-and-artifact-layout.md) — artifact layout and manifest schema.
- [ADR-009](./009-host-identifier-vs-cert-name.md) — cert `name` drives the default filename.
- [`../hcl-schema.md`](../hcl-schema.md) — updated schema reference.
