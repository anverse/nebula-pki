# Explicit `trust_bundle` block

* Status: accepted
* Deciders: fw
* Date: 2026-08-22 (revised 2026-10-03: any number of bundles, label as identity and file name,
  no signing rule, unique artifact paths)

> A bundle's file is named after its label (`trust_bundle "main"` writes `main.crt`), and the
> manifest CA map is `cas` (unrelated to this block's `ca_refs` field).

## Context and Problem Statement

[ADR-016](./016-ca-rotation-and-trust-bundles.md) made the trust bundle an emitted artifact with **implicit** membership: every declared CA that is not `archived = true`. It explicitly left the door open for a named trust-bundle block once a concrete need arrived. Two needs have now arrived:

1. **Bundle fan-out.** [ADR-021](./021-ca-cert-links.md)'s `link_crt` places a single CA's certificate into cert output directories so each directory is self-contained (the cert's `.key`, `.crt`, and `ca.crt`). But during a rotation the file a node's `pki.ca` must contain is the **bundle**, not any single CA cert — a directory carrying only one CA's cert breaks the rotation dance at step 2. There is no way to fan out the bundle; `link_crt` exists only on `ca` blocks, and the bundle is owned by no single CA.
2. **Transparency of rotation state.** Implicit membership makes the trust set an inference ("every block without `archived = true`") rather than a statement. The `archived` flag conflates two things — bundle exclusion and a signing ban — and rotation staging is expressed by toggling booleans across blocks instead of editing one visible list.

## Decision

Add labelled `trust_bundle` blocks that state trust membership **explicitly** via CA references ([ADR-025](./025-ca-references.md)) and carry their own `link_crt`. A config declares any number of them, including none. Trust bundles are **fully declarative**: a bundle exists only when a `trust_bundle` block declares it — there is no implicit bundle emitted under the hood (§2, superseding [ADR-016](./016-ca-rotation-and-trust-bundles.md)'s always-emit). Bundles describe trust sets only; they do not restrict which CA may sign (§3). The `archived` flag is **removed**, and so is `storage.trust_bundle_file` — a bundle's path now lives where the bundle is declared (`trust_bundle.path`), not in `storage`.

The `default` flag **stays on the `ca` block**. It decides which CA signs each cert — a signing concern with no relation to the trust bundle (the two axes of ADR-016). Placing it on the bundle would also break with multiple bundles: with more than one trust set, a per-bundle default is ambiguous (which bundle's default applies to a given cert?), whereas a single signing default among the CA declarations stays well-defined no matter how many bundles exist. The `trust_bundle` block deliberately owns only the trust axis.

```hcl
trust_bundle "main" {
  ca_refs  = [ca.current, ca.next]     # explicit trust membership
  path     = "out/bundles/main.crt"    # optional; default <out_dir>/bundles/<label>.crt
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
- A declared CA that is not listed in any bundle's `ca_refs` is valid: it is generated or read as usual, its manifest record is kept, and it may sign (§3). It is simply not part of that trust set.
- **Any number of `trust_bundle` blocks** may be declared (decided 2026-10-03; originally limited to one). Each describes one trust set, e.g. distinct trust sets for distinct cert populations, and a CA may be a member of several. Labels must be unique among `trust_bundle` blocks.

### 2. No `trust_bundle` block → no trust bundle

Bundles are **fully declarative**: a config with no `trust_bundle` block emits **no** bundle artifact and carries no `trust_bundles` manifest record. There is no implicit "every declared CA" bundle written under the hood. This **supersedes [ADR-016](./016-ca-rotation-and-trust-bundles.md)'s** decision to emit the bundle unconditionally — the value it sought (a stable, always-present `pki.ca` target) is now obtained by *declaring* a `trust_bundle`, not by magic. Declarative-over-implicit: the operator sees exactly what the config produces.

- A setup that wants no bundle points `pki.ca` at a CA cert directly (or fans one out with a `ca` block's own `link_crt`).
- A setup that wants a stable bundle path — recommended for anything that may ever rotate — declares a `trust_bundle` from day one, even single-member: `trust_bundle "main" { ca_refs = [ca.current] }`. The path (`out/bundles/main.crt`) then never changes when a second CA joins during rotation.

`storage.trust_bundle_file` is **removed** (no longer accepted; HCL's generic "Unsupported argument" error applies): the bundle's path belongs to the block that declares it; a `storage`-level override would be a second home for the same setting.

**Trade-off vs ADR-016.** A config that relied on the implicit bundle stops emitting `bundle.crt` until a `trust_bundle` block is added. Accepted deliberately (declarative-over-implicit); the mitigation is to declare the bundle up front, which also keeps the `pki.ca` path stable across a future rotation. This is a **behaviour** change rather than a removed keyword, and like the removals it ships without a migration path ([ADR-007](./007-schema-evolution.md) experimental-stage amendment).

### 3. No signing rule; `archived` is not replaced as a signing ban

`archived` had two effects:

| `archived` effect | Replacement |
|---|---|
| excluded from the emitted bundle | omitted from `trust_bundle.ca_refs` |
| may not sign certs | **none** — any declared CA may sign |

Trust bundles describe trust sets; they do not restrict signing (decided 2026-10-03). The first version of this ADR required every cert's signing CA, and the `default = true` CA, to be a member of the declared bundle, as a safety net against the partition foot-gun ADR-016 listed as its main negative. That rule was dropped:

- A CA outside every bundle is a legitimate setup: its certificate may reach nodes by other means, for example its own `link_crt` (ADR-021) with `pki.ca` pointing at the single CA cert.
- With several bundles there is no single trust set to check against; "member of at least one bundle" would still reject the setup above.
- `default = true` only says which CA signs certs that omit `cert.ca`; it carries no trust meaning.

During a rotation, moving `default = true` (step 2) is what stops the old CA from signing. Distribution order — shipping the bundle before the re-signed certs — remains the operator's job, as before.

Path uniqueness is validated across every block; see "Detailed rules".

### 4. `trust_bundle` `link_crt`

Same semantics as ADR-021, applied to the bundle artifact:

- Each entry is a directory; the symlink filename is the **basename of the bundle path**: `<label>.crt` by default, or `basename(path)` when set.
- Targets are relative (`filepath.Rel`), parent directories are created, correct links are no-ops, wrong-target links are recreated, regular files are never clobbered, stale links are cleaned up via manifest diff.

This closes the fan-out gap: an output directory listed in a bundle's `link_crt` carries a `<label>.crt` symlink (e.g. `main.crt`) whose content is correct before, during, and after a rotation — `pki.ca` points at one stable name the whole way through. With bundle fan-out available, per-CA `link_crt` becomes the niche option for consumers that deliberately pin a single CA; documentation should steer the default pattern to the bundle.

### 5. Manifest representation

```json
{
  "trust_bundles": {
    "main": {
      "path": "out/bundles/main.crt",
      "ca_fingerprints": ["..."],
      "links": [
        {"path": "out/hetzner/main.crt", "target": "../bundles/main.crt"}
      ]
    }
  }
}
```

- `trust_bundles` is a map keyed by bundle label, holding one record per declared `trust_bundle` block. With no blocks the key is absent. Each record carries `path`, `ca_fingerprints` (in `ca_refs` order) and `links` (same `{path, target}` shape as the per-CA `cas.<label>.links`).
- The CA record's `archived` field is **removed**. Whether a CA is trusted by a bundle is derivable: its fingerprint appears in that bundle's `ca_fingerprints`.
- **No manifest `schema_version` bump**: the former single `trust_bundle` object (always present under ADR-016) becomes the `trust_bundles` map, and `archived` is gone. These are consumer contract changes under [ADR-007](./007-schema-evolution.md)'s manifest-versioning stance, shipped **without** a bump under its experimental-stage amendment; the bump is deferred to the first manifest change after the tool is declared production-ready, when accumulated shape changes are versioned together.

### The rotation dance, revised

| Upstream step | `nebula.hcl` edit | Emitted result |
|---|---|---|
| 0. Steady state | `ca "current"` + `trust_bundle "main" { ca_refs = [ca.current] }` declared up front | one-cert bundle at a stable path (`out/bundles/main.crt`) |
| 1. Generate CA2 | add `ca "next"`; extend to `ca_refs = [ca.current, ca.next]` | bundle carries both; ship + reload |
| 2. Re-sign onto CA2 | move `default = true` to `next` (or canary via `cert.ca = ca.next`) | affected certs re-signed under `next` |
| 3. Drop CA1 from trust | remove `ca.current` from `ca_refs` | slimmer bundle; ship + reload. `current`'s record kept; it no longer signs because step 2 moved the default |
| 4. Retire CA1 | delete the `ca "current"` block (and key) | any forgotten `ca.current` reference fails the parse |

Declaring the `trust_bundle` at step 0 (not only when membership first diverges) keeps `pki.ca` pointed at one stable path across the whole rotation. Every trust-set change is then an edit to one visible list in one block, reviewable as a one-line diff.

### Detailed rules (decided 2026-10-02, revised 2026-10-03)

- **Label.** A `trust_bundle` label matches the CA label pattern `^[A-Za-z_][A-Za-z0-9_-]*$` and is unique among `trust_bundle` blocks.
- **Default path and file name.** A bundle is written to `<out_dir>/bundles/<label>.crt` unless `path` is set, so `trust_bundle "main"` writes `out/bundles/main.crt`, and its `link_crt` symlinks are named `main.crt`. The file name follows the label the operator wrote; bundles live in their own directory so a bundle and a CA with the same label do not share a default path.
- **Bundle order.** A bundle concatenates the member certificates in `ca_refs` order, and its `ca_fingerprints` follows the same order. Reordering `ca_refs` rewrites the bundle.
- **Source ranges.** Every `ca_refs` error (an element that is not a `ca.<label>` reference, a reference to an undeclared CA, a duplicate member, an empty list, a value that is not a list, a missing `ca_refs`) is prefixed with the offending expression's `file:line,col` range, exactly like `cert.ca` errors ([ADR-025](./025-ca-references.md)).
- **Identity is the label.** As for `ca` and `cert` blocks, the label is the manifest key and the identity. Renaming a label is a new bundle: it is written (to its new default path, or to its unchanged explicit `path`), the old record is dropped, the old file is released (below) unless the new bundle writes the same path, and the old symlinks are deleted unless a current block declares the same symlink path. The rewrite is not strictly necessary when nothing but the label changed, but it is the same straightforward behaviour as every other block.
- **A bundle is a planned action.** The planner alone decides whether a bundle is written, up to date, or released, and apply carries that out, so `--dry-run` shows exactly what a run does. It is written when it is not recorded yet, its path changed, the file is missing, a member CA is generated in this run, or the member fingerprints (in `ca_refs` order) differ from the recorded ones. A referenced CA swapped under an unchanged label never reaches the bundle planner: the run fails earlier ([ADR-027](./027-ca-pinned-to-label.md), 2026-10-04), so the bundle compares recorded fingerprints only.
- **Removed block, renamed label, or changed `path`: the file stays.** The previously written bundle file is **not deleted**. It stays on disk and the run prints a notice that the file is no longer managed, the same policy as stale cert artifacts. The manifest drops the old record (or records the new path). The bundle's managed symlinks *are* deleted, like any stale `link_crt` symlink (§4).
- **Unique artifact paths.** Every path the tool writes must be unique across the whole config: CA certificates and keys (with the encryption suffix), cert certificates and keys, bundle files, every `link_crt` symlink, and the manifest. A referenced CA's `cert_file` and `key_file` are inputs and must not be the target of any write. Paths are compared after resolving against the config directory and cleaning, so `out/x/` and `out/x` are the same. A clash names every owner of the path in one error, e.g. ``path out/s/main.crt is used by ca "a" (link_crt), ca "b" (link_crt) and trust_bundle "main" (link_crt)``. This also rejects a symlink that would replace the file it points at (`link_crt` naming the bundle's or CA's own directory). A written file must also not be a directory that holds another path, e.g. a bundle `path = "out/certs"` next to the default cert files (added 2026-10-04).
- **Link ownership.** Every planned symlink records which block owns it (a CA or a trust bundle) as well as the label, so a CA and a bundle with the same label never share links. The CLI reports `linked trust bundle "<label>"` for bundle symlinks.
- **Future idea, not built: opt-in cleanup.** Files that stop being managed (a renamed or removed bundle, a deleted `ca` block's cert and key, stale cert artifacts) are always kept today, with a notice. A later flag such as `--prune` could delete them instead, with keeping as the default. It would apply to every kind of released file, not only bundles.

## Relation to ADR-007

[ADR-007](./007-schema-evolution.md) names field removal as the trigger for introducing the `nebula_pki { schema = N }` block. Removing `archived` and `storage.trust_bundle_file`, and dropping the implicit always-emitted bundle, ship **without** schema versioning and without a migration path, under ADR-007's experimental-stage amendment: the tool is not yet used in production, so the removed fields simply stop parsing (generic HCL errors, no targeted rewrite messages) and configs relying on the implicit bundle stop emitting it until a `trust_bundle` block is declared.

## Consequences

### Positive

- The trust set is a declaration, not an inference; rotation staging is a reviewable one-line list edit.
- **Fully declarative**: no bundle artifact is written under the hood — a bundle exists iff a `trust_bundle` block declares it, so the config's output is exactly what the config says.
- Bundle fan-out makes `output_dir` directories genuinely self-contained across rotations — the gap that motivated this ADR.
- Any number of trust sets, each a separate artifact with its own fan-out.
- Artifact-path uniqueness turns accidental overwrites (a bundle onto a CA cert, a symlink onto its own target) into config errors.
- Two flags (`archived`, and the `default`-vs-`archived` interaction) are reduced to one; `ca` blocks describe CAs, the `trust_bundle` block describes trust.
- Dangling membership is impossible: references fail the parse when the target block is deleted.

### Negative

- **Breaking, no migration path**: configs using `archived` or `storage.trust_bundle_file` fail to parse with the generic HCL error. Accepted under the ADR-007 experimental-stage amendment (see above).
- **Breaking behaviour change vs ADR-016**: the implicit, always-emitted bundle is gone — a config with no `trust_bundle` block emits no `bundle.crt`. Configs that relied on it must declare a `trust_bundle` (declaring one up front also keeps the `pki.ca` path stable).
- Any config that wants a bundle now carries a `trust_bundle` block — a little boilerplate for the single-CA case, accepted as the cost of being declarative.
- `default` remains a flag on `ca` blocks, so the rotation flip still touches two blocks (remove from one, add to the other) — considered and accepted; moving it into the `trust_bundle` block was rejected to keep the bundle purely on the trust axis.
- One more block type in the schema and one more manifest field surface.
- No config-level guard against signing with a CA that no node trusts: the operator must keep `default` and `cert.ca` in step with what nodes trust (§3).

## Considered alternatives

### A. Signing default moves into the `trust_bundle` block (`default_ca = ca.next`)

Would make the `trust_bundle` block a single "rotation control panel" and structurally force the default to be a member. Rejected: the default decides which CA signs each cert — a signing concern that has nothing to do with the trust bundle, so the `ca` declarations are its natural home. The `trust_bundle` block would then own both axes ADR-016 was careful to separate; the signing default is meaningful even in configs with no `trust_bundle` block; and with multiple bundles a per-bundle default becomes ambiguous, while a default among the CA declarations does not. The membership constraint is enforced by validation instead.

### B. Keep `archived` alongside the `trust_bundle` block

Two mechanisms for the same state, forever documented and tested. Rejected for a hard removal (see Relation to ADR-007).

### C. `link_bundle` on `storage` instead of a `trust_bundle` block

Would close the fan-out gap alone, without explicit membership. Rejected: membership transparency is wanted anyway, and `storage` growing per-artifact link lists points the schema in the wrong direction; the `trust_bundle` block is the natural owner of both.

### D. Keep `storage.trust_bundle_file` alongside `trust_bundle.path`

Rejected: two homes for one setting, plus a permanent conflict rule when both are set. With the bundle explicit, its path belongs to its declaration (`trust_bundle.path`, default `<out_dir>/bundles/<label>.crt`).

### E. Keep the implicit always-emit bundle as a fallback when no `trust_bundle` block is declared

This is the option [ADR-016](./016-ca-rotation-and-trust-bundles.md) left open ("the implicit bundle could either remain as the default or be suppressed when any bundle block is present — to be decided in that future ADR"). This is that ADR; the fallback is **rejected**, for two reasons:

1. **An implicit bundle carries no `link_crt`, so it is unusable under the fan-out pattern this ADR exists to serve.** Certs fanned out to per-directory `output_dir` locations each need the trust anchor co-located ([ADR-021](./021-ca-cert-links.md)). Only a *declared* `trust_bundle` can carry a `link_crt` list; an implicit bundle would sit at `out/ca/bundle.crt` with no way to reach the directories that need it — present, but useless precisely in the multi-directory setups that motivated bundle fan-out (§4). A user relying on the fallback would find the bundle exists yet cannot be consumed where their certs live.
2. **Declarative-over-implicit / operator choice.** A bundle is meaningful only when the network trusts more than one CA — i.e. when rotating. A long-lived single-CA deployment (personal mesh, multi-year CA) never needs one and points `pki.ca` straight at `ca.crt` (§2); a deployment that will rotate is best served by declaring a `trust_bundle` from day one for a stable path. Emitting a bundle nobody asked for muddies that choice and re-introduces the "why did `bundle.crt` appear?" surprise. The two-tier guidance belongs in docs (readme, at the v0.2.0 cut), not in an implicit artifact — note that "always declare a bundle" is a `nebula-pki` recommendation for rotation-bound setups, not an upstream Nebula requirement (`pki.ca` upstream is just a CA cert file).

Retaining the fallback would also mean two membership models coexisting (implicit "every CA" vs explicit `ca_refs`) with no way for the implicit one to express "drop CA1 from trust" now that `archived` is gone — so it could not even carry a rotation correctly.

### F. Signing CA must be a bundle member (decided 2026-08-22, dropped 2026-10-03)

Every cert's signing CA, and the `default = true` CA, had to be in the declared bundle. Dropped because it forbids legitimate setups (a CA distributed through its own `link_crt`) and has no single trust set to check against once several bundles exist; see §3.

### G. Exactly one `trust_bundle` block (decided 2026-08-22, lifted 2026-10-03)

The first version allowed one block and deferred multiple bundles to a later ADR. The labelled form already reserved the syntax, and with label identity the manifest becomes a label-keyed map anyway, so the restriction was lifted in the same release instead of forcing a second manifest change later.

### H. Path as the bundle's identity, `bundle.crt` as default file name (decided 2026-10-02, revised 2026-10-03)

The bundle was identified by its path and defaulted to `<out_dir>/ca/bundle.crt`, so renaming the label rewrote nothing. Rejected: the default file name did not follow the label the operator wrote (`trust_bundle "main"` wrote `bundle.crt`), a path is not a stable identity across machines and checkouts, and it diverged from how `ca` and `cert` blocks behave.

## Links

- [ADR-016](./016-ca-rotation-and-trust-bundles.md) — implicit membership, the always-emit artifact, and `archived`; **amended by this ADR** (all three are superseded — membership is explicit, the bundle is emitted only when declared, and `archived` is gone; the two-axes model and the non-goals stand).
- [ADR-025](./025-ca-references.md) — `ca.<label>` reference syntax used by `ca_refs`, and the reserved-root convention behind the field name.
- [ADR-024](./024-rename-host-to-cert.md) — the `cert` block used in examples here.
- [ADR-021](./021-ca-cert-links.md) — `link_crt` semantics reused for the bundle.
- [ADR-007](./007-schema-evolution.md) — breaking-change policy; see the experimental-stage amendment.
- [Milestone v0.2](../milestones/v0.2.md) — iteration plan.
