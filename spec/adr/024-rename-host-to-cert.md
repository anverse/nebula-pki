# Rename the `host` block to `cert`

* Status: accepted
* Deciders: fw
* Date: 2026-08-22

## Context and Problem Statement

The per-certificate declaration has been a `host` block since the first schema:

```hcl
host "app_01" {
  name     = "app-01.mesh.internal"   # cert CN
  networks = ["10.42.1.10/16"]
  ca       = ca.next                   # signing CA reference
}
```

The name was chosen because certs are applied to hosts. But `nebula-pki` does exactly one
thing per block — issue a signed certificate (plus its key). It does **not** generate a
node's Nebula daemon config. Naming the block after a *host* over-claims the tool's scope
and collides with how Nebula itself uses the word "host". This ADR renames the block to
`cert` (`cert.name`, `cert.networks`, `cert.ca`, `cert.groups`, `cert.output_dir`,
`cert.in_pub`, …).

## Decision

Rename the block to **`cert`**. This is a **hard-switch breaking rename** under the
[ADR-007](./007-schema-evolution.md) experimental-stage amendment (2026-09-26): only `cert` is
accepted; a leftover `host` block fails with the generic HCL "Unsupported block type" error
and no targeted rewrite message. It ships as **its own release, first** in the schema-change
sequence (see "Release sequencing").

```hcl
cert "app_01" {
  name     = "app-01.mesh.internal"
  networks = ["10.42.1.10/16"]
  ca       = ca.next
}
```

### Scope of the rename (decided 2026-09-26)

The rename is not limited to the HCL keyword. The goal is that no "host" naming for the
per-certificate concept survives anywhere — config, manifest, on-disk layout, code, CLI
output, or spec. Because the tool is still experimental ([ADR-007](./007-schema-evolution.md)
2026-09-26 amendment), none of this carries a migration path.

1. **Manifest:** the top-level `hosts` map is renamed to **`certs`** (`certs.<label>.name`,
   `certs.<label>.ca`, `certs.<label>.artifacts`, …). The key is still the block label.
   **No `schema_version` bump** and no read-side migration: a manifest written by ≤ v0.1.6
   is not carried forward; regenerate `out/`.
2. **Default output directory:** `<storage.out_dir>/hosts/` becomes
   **`<storage.out_dir>/certs/`** for certs without an `output_dir`. Existing trees are not
   moved; a re-run against an old tree signs fresh certs into `certs/`.
3. **Codebase:** every identifier that names the per-certificate concept is renamed
   (`config.Cert`, `Config.Certs`, `CertArtifactPath`, `plan.KindCert`, `manifest.Cert`,
   `pki.SignCert`/`SignCertFromPub`/`CertResult`, `apply.SignedCerts`, …). "Host" survives
   only where it means a Nebula **node** or the machine the tool runs on (e.g. "the CA
   host", "every host trusts the bundle").
4. **CLI output:** all user-visible strings follow — `signed cert "x"`, `check`'s
   `certs=N`, dry-run `sign cert "x"`, validation/apply errors `cert "x": …`, the deadline
   report, rekey output, and help text.
5. **No special parse error** for the old `host` keyword (see Decision above).
6. **ADR files are renamed** where their filename or title carries the old block name, and
   every link across the repo is updated: ADR-009 → `009-cert-label-vs-cert-name.md`,
   ADR-017 → `017-cert-renewal-threshold.md`, ADR-020 → `020-output-dir-per-cert.md`. This
   ADR keeps its filename, since it records the rename itself.
7. **ADR body sweep:** every ADR is rewritten to speak of `cert` blocks, `cert.*` fields,
   the `certs` manifest map, and `out/certs/`, so a reader going through the ADRs in order
   never meets a `host` block that no longer exists. Where rewriting would change the
   historical meaning of a decision, the text is rephrased and linked to this ADR instead.

## Naming rationale

The decisive framing is that **Nebula's vocabulary splits into two dialects**:

- **Artifact / identity dialect** — `nebula-cert` (the upstream tool is named after the
  artifact), its `sign -name -networks -groups`, and `pki: { ca, cert, key }` in
  `config.yml`. This is what `nebula-pki` produces.
- **Topology / reachability dialect** — `static_host_map`, `lighthouse.hosts`, "each host
  runs Nebula." This is node/daemon-config territory, which `nebula-pki` deliberately does
  **not** touch.

Config keywords should come from the *first* dialect. "host" is the topology word; borrowing
it points users at scope the tool does not have. Prefer the word that names the artifact the
tool emits.

### Angle 1 — maintainer / scope integration

If slackhq adopted this, the clean story is: *"`nebula-cert` is one-shot; `nebula-pki` is
the declarative version — CAs, rotation, trust bundles, encryption-at-rest, many certs from
one file."* Both are **cert** tools; `nebula-pki` sits one level of *automation* up, not one
level of *abstraction* up. Naming the block `cert` keeps the family coherent and the
boundary legible. `host` implies the tool climbed the stack into node/config management. The
worst newcomer misconception is "does this generate my node's `config.yml`?" — `host
"app_01" {}` invites that read because Nebula calls nodes hosts; `cert "app_01" {}` closes
the question at the keyword. The product is named `nebula-pki`, not `nebula-hosts`: `cert`
blocks agree with the product name, `host` blocks fight it.

### Angle 2 — user comprehension, beginner → veteran

- **Beginner:** first contact is `nebula-cert sign -name laptop`; the fresh model is "I make
  a cert for my laptop." `cert "laptop"` maps 1:1. `host` forces the bridge "I'm defining a
  host → oh, it emits a cert."
- **Intermediate:** knows `pki: { cert, key }`; a `cert` block fills `pki.cert`/`pki.key`
  directly. `host` adds a translation hop.
- **Veteran back after months (the strongest case):** the recurring question is "if I edit
  this block, am I touching my node's config or just its cert?" With `cert` the keyword
  answers it permanently. `host` re-taxes the operator on every return visit. This is the
  "keeps their mind sane long-term" property.

### The three points weighed

1. **Clean PKI scope (for `cert`):** the strong argument, and it strengthens the more
   production-critical the tool is — scope legibility compounds.
2. **"A cert is a side effect of defining a node" (for `host`):** the real counter, best
   stated as "`networks`/`groups` are node properties, not cert properties." It dissolves on
   inspection: in Nebula those fields are **embedded in the certificate** — `nebula-cert
   sign` puts `-networks`/`-groups` *onto* the cert and `nebula-cert print` reads them *out
   of* it. So `cert.networks` is accurate: "the networks this cert authorizes."
3. **Multiple certs per host (for `host`):** flawed, and dropped. Today one node = one block
   regardless; more certs = more blocks, which reads more naturally as more `cert` blocks
   than as a `host` mysteriously split in two.

### The one real cost (and its mitigation)

Nebula's community reflex is "host," so some users will momentarily look for a `host` block.
Mitigation: one docs line ("one `cert` block per node"). That turns a one-time "huh" into a
one-time lesson that *reinforces* the scope boundary — a net positive, not a lingering tax.
(A targeted parse error naming the rewrite was originally planned; it was dropped under the
experimental-stage posture, see Decision.)

## Release sequencing

This rename ships as **its own `v0.1.x` release, before** the CA-reference and trust-bundle
iterations. Reasons:

- It is a pure mechanical breaking rename with no new behaviour; isolating it keeps the
  changelog and migration story clean ("this release renames `host` → `cert`, here is the
  rewrite") instead of burying a breaking change inside feature work.
- Doing it **first** means the later iterations land on the final `cert` keyword — the
  CA-reference work operates on `cert.ca` and the trust-bundle examples/testdata use `cert`
  blocks from the start, so examples and `.txtar` fixtures are rewritten **once**, not twice.

The ADRs that follow this one ([ADR-025](./025-ca-references.md),
[ADR-026](./026-trust-bundle-block.md)) are written directly against the `cert` keyword; this
ADR does not depend on their syntax. See the [Milestone v0.2](../milestones/v0.2.md)
iteration plan.

## Affected surfaces (ripple)

- **ADRs:** every ADR mentioning the `host` block, `host.*` fields, the `hosts` manifest map,
  or `out/hosts/` gets the body sweep (see scope item 7) and loses its "Terminology
  (amended by ADR-024)" notice. The largest changes:
  - [ADR-009](./009-cert-label-vs-cert-name.md) is reframed as "cert block label (HCL
    identifier) vs cert CN (`name`)" and renamed to `009-cert-label-vs-cert-name.md`. The
    character-rule and rate-of-change rationale is unchanged; only the narrative changes
    (the label is the cert's local handle, not a host's).
  - [ADR-017](./017-cert-renewal-threshold.md) is renamed to `017-cert-renewal-threshold.md`
    and [ADR-020](./020-output-dir-per-cert.md) to `020-output-dir-per-cert.md`.
  - [ADR-002](./002-state-and-artifact-layout.md) gets the manifest example and field list
    (`certs.*`) plus the `out/certs/` layout.
  - [ADR-011](./011-output-blocks-are-directories.md), [ADR-015](./015-multiple-cas-per-config.md),
    [ADR-016](./016-ca-rotation-and-trust-bundles.md) and [ADR-018](./018-in-pub-air-gapped-signing.md)
    get field-path and prose updates.
- **Spec:** `spec/readme.md`, `spec/hcl-schema.md`, `spec/hcl-schema.formal.json` (block
  name, `$defs`, every field path, validation rules), and the milestone docs' links.
- **Code:** `internal/config` (decode, validation messages, `certsSubdir = "certs"`),
  `internal/manifest` (`Certs map[string]Cert` with `json:"certs"`), `internal/plan`,
  `internal/pki`, `internal/apply`, and `internal/cli` (including `rekey`), with all
  user-visible strings.
- **Tests:** unit tests, every e2e `.txtar` (HCL, `out/hosts/` paths, output assertions),
  and the smoke-test harness.
- **Docs:** `readme.md`, `AGENTS.md`, and all `examples/`.

## Consequences

### Positive

- The keyword encodes the tool's scope boundary permanently: `nebula-pki` deals in certs,
  not node configs. The "does this touch my daemon config?" question stops recurring.
- Aligns the config with `nebula-cert` and `pki.cert`, shortening the mental bridge for
  users at every level.
- `cert.name` reads consistently ("the certificate's name" = its CN).

### Negative

- **Breaking, with no migration path**: every existing `host` block must be rewritten to
  `cert`, the manifest's `hosts` map becomes `certs` (no `schema_version` bump), and default
  artifacts move from `out/hosts/` to `out/certs/`, so existing `out/` trees must be
  regenerated. Accepted under the ADR-007 experimental-stage amendment.
- Momentary friction for Nebula users conditioned on "host" (mitigated as above).
- Broad but shallow churn across ADRs, schema, examples, and testdata.

## Considered alternatives

### Keep `host`

Rejected. Its best case rests on `networks`/`groups` feeling node-ish and on matching
Nebula's `static_host_map`/`lighthouse.hosts` vocabulary. But those fields are literally
certificate fields in Nebula's model, and matching the *topology* dialect is precisely the
wrong signal for a tool that only issues certs — it implies topology/config management the
tool does not do. The "one host, many certs" headroom argument is flawed (one block = one
cert today regardless).

## Links

- [ADR-009](./009-cert-label-vs-cert-name.md) — the label-vs-CN split, reframed by this rename.
- [ADR-007](./007-schema-evolution.md) — pre-1.0 breaking-change amendment.
- [ADR-025](./025-ca-references.md) — next iteration; changes `cert.ca` to a `ca.<label>` reference.
- [ADR-026](./026-trust-bundle-block.md) — later iteration; the explicit trust-bundle block, written against `cert`.
- [Milestone v0.2](../milestones/v0.2.md) — where this rename is scheduled (first of the schema iterations).
