# Explicit `trust_bundle` block

* Status: accepted
* Deciders: fw
* Date: 2026-08-22

> The emitted artifact file is `bundle.crt` (a filename, not the block keyword), and the
> manifest CA map is `cas` (unrelated to this block's `ca_refs` field).

## Context and Problem Statement

[ADR-016](./016-ca-rotation-and-trust-bundles.md) made the trust bundle an emitted artifact with **implicit** membership: every declared CA that is not `archived = true`. It explicitly left the door open for a named trust-bundle block once a concrete need arrived. Two needs have now arrived:

1. **Bundle fan-out.** [ADR-021](./021-ca-cert-links.md)'s `link_crt` places a single CA's certificate into cert output directories so each directory is self-contained (the cert's `.key`, `.crt`, and `ca.crt`). But during a rotation the file a node's `pki.ca` must contain is the **bundle**, not any single CA cert — a directory carrying only one CA's cert breaks the rotation dance at step 2. There is no way to fan out the bundle; `link_crt` exists only on `ca` blocks, and the bundle is owned by no single CA.
2. **Transparency of rotation state.** Implicit membership makes the trust set an inference ("every block without `archived = true`") rather than a statement. The `archived` flag conflates two things — bundle exclusion and a signing ban — and rotation staging is expressed by toggling booleans across blocks instead of editing one visible list.

## Decision

Add a labelled `trust_bundle` block that states trust membership **explicitly** via CA references ([ADR-025](./025-ca-references.md)) and carries the bundle's own `link_crt`. The trust bundle is **fully declarative**: it exists only when a `trust_bundle` block is declared — there is no implicit bundle emitted under the hood (§2, superseding [ADR-016](./016-ca-rotation-and-trust-bundles.md)'s always-emit). The `archived` flag is **removed**, and so is `storage.trust_bundle_file` — the bundle's path now lives where the bundle is declared (`trust_bundle.path`), not in `storage`.

The `default` flag **stays on the `ca` block**. It decides which CA signs each cert — a signing concern with no relation to the trust bundle (the two axes of ADR-016). Placing it on the bundle would also foreclose the deferred multiple-bundles future: with more than one trust set, a per-bundle default is ambiguous (which bundle's default applies to a given cert?), whereas a single signing default among the CA declarations stays well-defined no matter how many bundles exist. The `trust_bundle` block deliberately owns only the trust axis.

```hcl
trust_bundle "main" {
  ca_refs  = [ca.current, ca.next]     # explicit trust membership
  path     = "out/ca/bundle.crt"       # optional; default <out_dir>/ca/bundle.crt
  link_crt = ["out/hetzner", "out/aws"]
}

ca "current" { name = "mesh-2026" }

ca "next" {
  name    = "mesh-2027"
  default = true                       # signing default stays here
}
```

## Naming rationale

Two keywords are introduced here — the block and its members field. The reasoning (research
and judgement) behind each:

### The block: `trust_bundle` (not `bundle`, not `ca_trust_bundle`)

- **Name states the purpose; the body states the content.** A block keyword should carry the
  block's purpose; the body already carries its content. The body is a list of CA references,
  so the CA-ness is established there — the keyword spends its characters on the purpose
  ("trust"), not on re-stating "CA".
- **Consistency with what already shipped.** The manifest field and internal API are already
  `trust_bundle`/`TrustBundle`; reusing the word gives one term across config, manifest, and
  code rather than a synonym readers must reconcile.
- **`bundle` rejected:** too generic ("a bundle of *what*?") and a namespace hog — it would
  spend the generic word on this narrow concept.
- **`ca_trust_bundle` rejected:** stutters against the body (`ca_trust_bundle { ca_refs = … }`
  says "CA" three ways) and over-specifies. Kept as the documented fallback if beginner
  testing ever shows the CA link isn't landing. (Note Nebula itself does not brand this
  "trust bundle"; its destination field is the CA-centric `pki.ca`. So "trust bundle" aligns
  with generic PKI usage and our own manifest, not specifically with Nebula.)

### The members field: `ca_refs` (not `cas`, `ca`, `ca_list`, or `members`)

- **Lists take a legible plural.** Terraform/HashiCorp convention is plural nouns for
  list-valued attributes (`security_groups`, `subnet_ids`) and singular keywords for
  repeatable *blocks*. This is a list attribute → plural. But the plural must read: `cas`
  (the bare acronym pluralised) reads as an opaque token and fails the "six-months-later,
  what is this?" test, so it is rejected.
- **Why not bare `ca`, when `cert.ca` uses it?** Because `cert.ca` is a **scalar** and this
  is a **list** — arity is the difference (see [ADR-025](./025-ca-references.md)). `cert.ca =
  ca.next` reads cleanly for one value. `ca = [ca.current, ca.next]` reads as "ca equals a
  list of cas": the singular name fights the list value and the root token repeats. A list
  therefore takes a plural, not bare `ca`.
- **`ca_refs` chosen:** keeps the `ca` stem (CA-ness obvious at a glance), the `_refs` suffix
  says "a list of references", it is accurate (the values *are* references), and the plural
  pairs naturally with the scalar `cert.ca` (one CA vs many). `members` was the runner-up
  (matches the "membership" language below) but drops the `ca` stem; `ca_list` uses an
  un-idiomatic `_list` suffix.

### 1. Membership

- `ca_refs` is a non-empty list of `ca.<label>` references. Duplicates are an error. Every reference must resolve to a declared `ca` block (a dangling reference is a parse-time error — deleting a `ca` block that a bundle still lists fails loudly, unlike the silent string-era alternative).
- When a `trust_bundle` is declared, a declared CA **not** listed in its `ca_refs` is valid: its manifest record is kept (history is never deleted by omission), it simply is not trusted and — via the signing rule below — may not sign. This is exactly the state `archived = true` used to express, minus the flag.
- **Exactly one** `trust_bundle` block is allowed for now. Multiple bundles (distinct trust sets for distinct cert populations) remain a future, additive ADR — the labelled form is chosen so that step is a lift of a restriction, not a syntax change.

### 2. No `trust_bundle` block → no trust bundle

The bundle is **fully declarative**: a config with no `trust_bundle` block emits **no** bundle artifact and carries no `trust_bundle` manifest record. There is no implicit "every declared CA" bundle written under the hood. This **supersedes [ADR-016](./016-ca-rotation-and-trust-bundles.md)'s** decision to emit the bundle unconditionally — the value it sought (a stable, always-present `pki.ca` target) is now obtained by *declaring* a `trust_bundle`, not by magic. Declarative-over-implicit: the operator sees exactly what the config produces.

- A setup that wants no bundle points `pki.ca` at a CA cert directly (or fans one out with a `ca` block's own `link_crt`).
- A setup that wants a stable bundle path — recommended for anything that may ever rotate — declares a `trust_bundle` from day one, even single-member: `trust_bundle "main" { ca_refs = [ca.current] }`. The path then never changes when a second CA joins during rotation.

`storage.trust_bundle_file` is **removed** (no longer accepted; HCL's generic "Unsupported argument" error applies): the bundle's path belongs to the block that declares it; a `storage`-level override would be a second home for the same setting.

**Trade-off vs ADR-016.** A config that relied on the implicit bundle stops emitting `bundle.crt` until a `trust_bundle` block is added. Accepted deliberately (declarative-over-implicit); the mitigation is to declare the bundle up front, which also keeps the `pki.ca` path stable across a future rotation. This is a **behaviour** change rather than a removed keyword, and like the removals it ships without a migration path ([ADR-007](./007-schema-evolution.md) experimental-stage amendment).

### 3. Signing validation replaces the `archived` guard

`archived` had two effects; both are subsumed:

| `archived` effect | Replacement |
|---|---|
| excluded from the emitted bundle | omitted from `trust_bundle.ca_refs` |
| may not sign certs | validation: **every cert's resolved signing CA must be a member of the declared bundle** |

The signing rule applies **only when a `trust_bundle` is declared**: then every cert's resolved signing CA must appear in its `ca_refs`. With no `trust_bundle` block there is no trust set and no such constraint — any declared CA may sign, as before this feature. When a bundle *is* declared, the rule catches, at config level, the partition foot-gun ADR-016 listed as its main negative: a `default = true` or `cert.ca` pointing at a CA that is not in the bundle is an **error**, not an emitted artifact that partitions the network. (The tool still cannot enforce *distribution* ordering; that remains the operator's job.)

Additional validation:

- `default = true` on a CA not listed in the declared bundle → error (replaces the old `archived && default` conflict check).
- **`link_crt` symlink-path uniqueness (symmetric).** Each `link_crt` list (on any `ca` block and on the `trust_bundle`) must have non-empty entries and no duplicate directories within itself. Across **all** of them, the set of resolved symlink paths — `<directory>/<symlink-filename>` — must be pairwise distinct. A CA cert symlink and the bundle symlink *may* share a directory when their filenames differ (e.g. `current.crt` and `bundle.crt` both in `out/hetzner`), but no two sources may write the same `<dir>/<filename>`. This is checked symmetrically and catches CA-vs-CA, CA-vs-`trust_bundle`, and `trust_bundle`-vs-CA collisions alike (e.g. a `ca` whose `out_crt` basename is `bundle.crt` colliding with the bundle's default filename in a shared directory).

### 4. `trust_bundle` `link_crt`

Same semantics as ADR-021, applied to the bundle artifact:

- Each entry is a directory; the symlink filename is the **basename of the bundle path** (`bundle.crt` by default, or `basename(path)` when set).
- Targets are relative (`filepath.Rel`), parent directories are created, correct links are no-ops, wrong-target links are recreated, regular files are never clobbered, stale links are cleaned up via manifest diff.

This closes the fan-out gap: an output directory listed in both a CA's (or no CA's) `link_crt` and the bundle's `link_crt` carries a `bundle.crt` symlink whose content is correct before, during, and after a rotation — `pki.ca` points at one stable name the whole way through. With bundle fan-out available, per-CA `link_crt` becomes the niche option for consumers that deliberately pin a single CA; documentation should steer the default pattern to the bundle.

### 5. Manifest representation

```json
{
  "trust_bundle": {
    "label": "main",
    "path": "out/ca/bundle.crt",
    "ca_fingerprints": ["..."],
    "links": [
      {"path": "out/hetzner/bundle.crt", "target": "../ca/bundle.crt"}
    ]
  }
}
```

- The `trust_bundle` record exists only when a `trust_bundle` block is declared; it carries `label` (the block's label) and `links` (same `{path, target}` shape as the manifest's per-CA `cas.<label>.links`). A config with no `trust_bundle` block has **no** `trust_bundle` key in the manifest.
- The CA record's `archived` field is **removed**. The archived state is derivable: a CA present in the manifest whose fingerprint is absent from `trust_bundle.ca_fingerprints` is not trusted.
- **No manifest `schema_version` bump**: `links` and `label` are additive; `archived` was `omitempty` and present only in mid-rotation manifests. Consumers that read it (none known) fall back to the fingerprint derivation. The `trust_bundle` record also changes from *always present* (ADR-016 always-emit) to present only when a block is declared — a consumer contract change under [ADR-007](./007-schema-evolution.md)'s manifest-versioning stance. Shipped **without** a bump under the [ADR-007](./007-schema-evolution.md) experimental-stage amendment; the manifest `schema_version` bump is deferred to the first manifest change after the tool is declared production-ready, when accumulated shape changes are versioned together.

### The rotation dance, revised

| Upstream step | `nebula.hcl` edit | Emitted result |
|---|---|---|
| 0. Steady state | `ca "current"` + `trust_bundle "main" { ca_refs = [ca.current] }` declared up front | one-cert bundle at a stable path |
| 1. Generate CA2 | add `ca "next"`; extend to `ca_refs = [ca.current, ca.next]` | bundle carries both; ship + reload |
| 2. Re-sign onto CA2 | move `default = true` to `next` (or canary via `cert.ca = ca.next`) | affected certs re-signed under `next` |
| 3. Drop CA1 from trust | remove `ca.current` from `ca_refs` | slimmer bundle; ship + reload. `current`'s record kept; it can no longer sign (validation) |
| 4. Retire CA1 | delete the `ca "current"` block (and key) | any forgotten `ca.current` reference fails the parse |

Declaring the `trust_bundle` at step 0 (not only when membership first diverges) keeps `pki.ca` pointed at one stable path across the whole rotation. Every trust-set change is then an edit to one visible list in one block, reviewable as a one-line diff.

## Relation to ADR-007

[ADR-007](./007-schema-evolution.md) names field removal as the trigger for introducing the `nebula_pki { schema = N }` block. Removing `archived` and `storage.trust_bundle_file`, and dropping the implicit always-emitted bundle, ship **without** schema versioning and without a migration path, under ADR-007's experimental-stage amendment: the tool is not yet used in production, so the removed fields simply stop parsing (generic HCL errors, no targeted rewrite messages) and configs relying on the implicit bundle stop emitting it until a `trust_bundle` block is declared.

## Consequences

### Positive

- The trust set is a declaration, not an inference; rotation staging is a reviewable one-line list edit.
- **Fully declarative**: no bundle artifact is written under the hood — a bundle exists iff a `trust_bundle` block declares it, so the config's output is exactly what the config says.
- Bundle fan-out makes `output_dir` directories genuinely self-contained across rotations — the gap that motivated this ADR.
- The signing-CA-must-be-trusted validation converts ADR-016's worst operational foot-gun into a config error.
- Two flags (`archived`, and the `default`-vs-`archived` interaction) are reduced to one; `ca` blocks describe CAs, the `trust_bundle` block describes trust.
- Dangling membership is impossible: references fail the parse when the target block is deleted.

### Negative

- **Breaking, no migration path**: configs using `archived` or `storage.trust_bundle_file` fail to parse with the generic HCL error. Accepted under the ADR-007 experimental-stage amendment (see above).
- **Breaking behaviour change vs ADR-016**: the implicit, always-emitted bundle is gone — a config with no `trust_bundle` block emits no `bundle.crt`. Configs that relied on it must declare a `trust_bundle` (declaring one up front also keeps the `pki.ca` path stable).
- Any config that wants a bundle now carries a `trust_bundle` block — a little boilerplate for the single-CA case, accepted as the cost of being declarative.
- `default` remains a flag on `ca` blocks, so the rotation flip still touches two blocks (remove from one, add to the other) — considered and accepted; moving it into the `trust_bundle` block was rejected to keep the bundle purely on the trust axis.
- One more block type in the schema and one more manifest field surface.

## Considered alternatives

### A. Signing default moves into the `trust_bundle` block (`default_ca = ca.next`)

Would make the `trust_bundle` block a single "rotation control panel" and structurally force the default to be a member. Rejected: the default decides which CA signs each cert — a signing concern that has nothing to do with the trust bundle, so the `ca` declarations are its natural home. The `trust_bundle` block would then own both axes ADR-016 was careful to separate; the signing default is meaningful even in configs with no `trust_bundle` block; and under the deferred multiple-bundles future a per-bundle default becomes ambiguous, while a default among the CA declarations does not. The membership constraint is enforced by validation instead.

### B. Keep `archived` alongside the `trust_bundle` block

Two mechanisms for the same state, forever documented and tested. Rejected for a hard removal (see Relation to ADR-007).

### C. `link_bundle` on `storage` instead of a `trust_bundle` block

Would close the fan-out gap alone, without explicit membership. Rejected: membership transparency is wanted anyway, and `storage` growing per-artifact link lists points the schema in the wrong direction; the `trust_bundle` block is the natural owner of both.

### D. Keep `storage.trust_bundle_file` alongside `trust_bundle.path`

Rejected: two homes for one setting, plus a permanent conflict rule when both are set. With the bundle explicit, its path belongs to its declaration (`trust_bundle.path`, default `<out_dir>/ca/bundle.crt`).

### E. Keep the implicit always-emit bundle as a fallback when no `trust_bundle` block is declared

This is the option [ADR-016](./016-ca-rotation-and-trust-bundles.md) left open ("the implicit bundle could either remain as the default or be suppressed when any bundle block is present — to be decided in that future ADR"). This is that ADR; the fallback is **rejected**, for two reasons:

1. **An implicit bundle carries no `link_crt`, so it is unusable under the fan-out pattern this ADR exists to serve.** Certs fanned out to per-directory `output_dir` locations each need the trust anchor co-located ([ADR-021](./021-ca-cert-links.md)). Only a *declared* `trust_bundle` can carry a `link_crt` list; an implicit bundle would sit at `out/ca/bundle.crt` with no way to reach the directories that need it — present, but useless precisely in the multi-directory setups that motivated bundle fan-out (§4). A user relying on the fallback would find the bundle exists yet cannot be consumed where their certs live.
2. **Declarative-over-implicit / operator choice.** A bundle is meaningful only when the network trusts more than one CA — i.e. when rotating. A long-lived single-CA deployment (personal mesh, multi-year CA) never needs one and points `pki.ca` straight at `ca.crt` (§2); a deployment that will rotate is best served by declaring a `trust_bundle` from day one for a stable path. Emitting a bundle nobody asked for muddies that choice and re-introduces the "why did `bundle.crt` appear?" surprise. The two-tier guidance belongs in docs (readme, at the v0.2.0 cut), not in an implicit artifact — note that "always declare a bundle" is a `nebula-pki` recommendation for rotation-bound setups, not an upstream Nebula requirement (`pki.ca` upstream is just a CA cert file).

Retaining the fallback would also mean two membership models coexisting (implicit "every CA" vs explicit `ca_refs`) with no way for the implicit one to express "drop CA1 from trust" now that `archived` is gone — so it could not even carry a rotation correctly.

## Links

- [ADR-016](./016-ca-rotation-and-trust-bundles.md) — implicit membership, the always-emit artifact, and `archived`; **amended by this ADR** (all three are superseded — membership is explicit, the bundle is emitted only when declared, and `archived` is gone; the two-axes model and the non-goals stand).
- [ADR-025](./025-ca-references.md) — `ca.<label>` reference syntax used by `ca_refs`, and the reserved-root convention behind the field name.
- [ADR-024](./024-rename-host-to-cert.md) — the `cert` block used in examples here.
- [ADR-021](./021-ca-cert-links.md) — `link_crt` semantics reused for the bundle.
- [ADR-007](./007-schema-evolution.md) — breaking-change policy; see the experimental-stage amendment.
- [Milestone v0.2](../milestones/v0.2.md) — iteration plan.
