# Multiple CAs per configuration file

## Status

accepted — supersedes [ADR-010](./010-single-ca-per-config.md)

## Context

[ADR-010](./010-single-ca-per-config.md) restricted a configuration file to exactly one `ca` block and deferred multi-CA support as YAGNI. That call was correct for the early milestones: it kept the manifest single-rooted, removed a class of validation rules, and the "one HCL file per CA" workaround covered the only motivating case at the time (isolated `dev`/`staging`/`prod` environments).

The constraint stops being correct the moment **CA rotation** enters scope. Nebula CAs expire — one year by default — and the only safe way across that boundary is an **overlap window** in which two CAs are trusted simultaneously while host certificates are re-signed from the old CA onto the new one (see the upstream [Rotating a Certificate Authority](https://nebula.defined.net/docs/guides/rotating-certificate-authority/) guide, and [ADR-016](./016-ca-rotation-and-trust-bundles.md)). Rotation is therefore not an exotic feature; it is the one operational task every long-lived mesh must perform, and it is intrinsically a **two-CA** state.

The "two HCL files" workaround does not model rotation well:

- The two CAs are not independent environments; they are the *same* mesh in transition. Splitting them across files means no single `nebula-pki` run sees both, so the tool cannot emit a combined trust bundle, cannot decide which CA should sign a given host, and cannot report rotation progress.
- The host list is shared between old and new CA. Duplicating it across two files invites drift exactly when correctness matters most.

ADR-010 anticipated this: its "Forward compatibility is preserved" section sketched the additive multi-CA shape and named the trigger — "revisited if and when multiple users independently ask for in-file multi-CA support." Rotation is a stronger trigger than user demand: it is a first-class workflow the tool cannot otherwise express.

## Decision

A configuration file may declare **one or more** CAs. Two shapes coexist:

### Unlabelled CA (unchanged, back-compatible)

A single `ca { ... }` block with no label parses exactly as it does today. Single-CA configs do not change in any way.

```hcl
ca {
  name     = "mesh-2026"
  duration = "8760h"
}

host "app_01" {
  networks = ["10.42.1.10/16"]
}
```

### Labelled CAs (new, opt-in)

Adding labels opts into the multi-CA shape. Each `ca "<label>" { ... }` is an independent CA — generated or referenced — with its own fields.

```hcl
ca "current" {
  name     = "mesh-2026"
  duration = "8760h"
}

ca "next" {
  name     = "mesh-2027"
  duration = "8760h"
}

host "app_01" {
  ca       = "current"        # which CA signs THIS host
  networks = ["10.42.1.10/16"]
}
```

### Rules

- **Cardinality.** Zero `ca` blocks is an error (unchanged). One unlabelled block is the legacy shape. One or more labelled blocks is the multi-CA shape. Mixing a labelled and an unlabelled block in the same file is an error — pick one style.
- **CA labels** follow the same identifier rules as host labels (`^[A-Za-z_][A-Za-z0-9_-]*$`) and must be unique within the file.
- **`ca.default`** is an optional boolean on a `ca` block marking it the default signing CA. **At most one** CA may set `default = true`; more than one is a validation error. It is meaningful only in the multi-CA shape (setting it on a lone unlabelled CA is an error — there is nothing to default among).
- **`host.ca`** selects the signing CA by label. It is:
  - **forbidden** when the file has a single (unlabelled) CA — there is nothing to disambiguate;
  - **optional** when a CA is marked `default = true` — omitting `host.ca` uses the default, setting it selects a non-default CA (an "alias");
  - **required** when the file has more than one CA **and** none is marked `default` — every host must then name its CA explicitly.

This mirrors the Terraform provider model — one default, others selected by name, resources omit the selector to get the default — but keeps the default *on a CA block* (`default = true`) rather than relying on an unlabelled block. Every CA therefore retains a label, which the multi-bundle forward-compat path ([ADR-016](./016-ca-rotation-and-trust-bundles.md)) depends on: a future `bundle.cas = [...]` list references CAs by label, and an unlabelled default could not be named there.

```hcl
ca "current" {
  name    = "mesh-2026"
  default = true            # signs hosts that omit `host.ca`
}

ca "next" {
  name = "mesh-2027"
}

host "app_01" { networks = ["10.42.1.10/16"] }                 # signed by current (default)
host "app_02" {                                                # signed by next (alias)
  ca = "next"
  networks = ["10.42.1.11/16"]
}
```

### Per-CA restrictions apply to the host's signing CA

`ca.groups`, `ca.networks`, and `ca.unsafe_networks` restrictions are validated against each host **relative to the CA that signs it**. A host signed by `current` is checked against `current`'s restrictions; a host signed by `next` against `next`'s. This is what makes a clean rotation possible: the new CA can carry identical restrictions, or deliberately tightened ones, and validation follows the signing relationship.

## Why now, and why additive

The single-CA schema is a strict subset of this one, so nothing that parses today changes meaning:

- Unlabelled `ca {}` → unchanged.
- `host.ca` and `ca.default` are new fields; absent means "the one CA."

Doing this **before the v0.1 freeze** is deliberate. v0.1 freezes the HCL surface for the 0.1.x line. Multi-CA is foundational — rotation, trust bundles, and the manifest's CA shape all build on it. Introducing it after v0.1 would force a breaking schema change (the `nebula_pki { schema = 2 }` mechanism of [ADR-007](./007-schema-evolution.md)) for something we can see coming now. The additive path described in ADR-010 is available today; we take it.

## Manifest impact

The manifest grows a `cas` map keyed by CA label. The legacy single-CA `ca` object is retained for back-compat when the config uses the unlabelled form. Per-host records gain a `ca` field naming the signing CA label (the existing `ca_fingerprint` already pins the exact CA cert). Full schema in [ADR-002](./002-state-and-artifact-layout.md).

## Consequences

### Positive

- Rotation becomes expressible declaratively (ADR-016): two CAs in one file, one mesh, one run, one manifest, one trust bundle.
- The host list lives in exactly one place during rotation; no cross-file duplication.
- Environment isolation (`dev`/`prod`) still works the old way — separate files — for operators who prefer it. This ADR does not force multi-CA on anyone.
- The same machinery generalises to the v1→v2 / IPv6 certificate migration, which is also a dual-trust transition (noted, not built here — see [ADR-016](./016-ca-rotation-and-trust-bundles.md)).

### Negative

- New validation surface: `host.ca` references an undeclared CA; labelled/unlabelled mixing; more than one CA marked `default = true`; `default = true` on a lone unlabelled CA; `host.ca` set in a single-CA file; ambiguous signing CA (>1 CA, no default, host without `host.ca`); per-CA restriction scoping. All are enumerated in [`hcl-schema.md`](../hcl-schema.md#validation-rules).
- The manifest is no longer single-rooted in the labelled form. Downstream consumers that read `ca` must learn `cas` (the back-compat `ca` object covers the legacy form).
- "At most one default" is a cross-block invariant rather than a structural one — it must be checked, not enforced by the grammar. The cost is small (one pass over the CA list) and is the price of co-locating the default with its CA instead of in a detached pointer.
- Two name-like axes on CAs (the label vs. `ca.name`) mirror the host label-vs-name split of [ADR-009](./009-host-identifier-vs-cert-name.md); the same reasoning and the same potential for confusion apply.

## Considered alternatives

### A. Keep ADR-010; rotation via two files plus a concatenation step

Rejected. A standalone "concatenate these two CA certs" step can produce a bundle, but it cannot decide which CA signs which host, cannot keep the host list single-sourced, and cannot report rotation progress in one manifest. It pushes the coordination back onto the operator, which is the toil the tool exists to remove.

### B. A dedicated rotation primitive instead of general multi-CA

A purpose-built CA shape with a baked-in "previous/next CA" pointer, narrower than general multi-CA. Rejected: it is a less general answer to a more general need (staging a second CA, signing different hosts under different CAs, the v1→v2 migration) and it would itself need replacing the first time a second legitimate multi-CA use appears. General labelled CAs cost little more and subsume the rotation case.

### C. How the default signing CA is expressed

Three mechanisms were considered for "which CA signs hosts that don't name one."

**C1 — root-level `default_ca = "label"`.** A top-level field naming the default. Rejected: it detaches the decision from the CA blocks (a second place to edit during a rotation flip), and it duplicates the label as a free-floating string. It works, but reads least naturally.

**C2 — unlabelled `ca {}` is the default, labelled `ca "alias" {}` are alternates (pure Terraform `provider` model).** The most familiar shape, and the closest literal copy of Terraform. Rejected for one decisive reason: it requires the default CA to be **unlabelled**, but the multi-bundle forward-compat path ([ADR-016](./016-ca-rotation-and-trust-bundles.md)) references CAs by label in `bundle.cas = [...]`. An unlabelled default could never appear in a bundle list. It also reverses this ADR's "no labelled/unlabelled mixing" rule, reintroducing the implicit/explicit blend ADR-010 rejected.

**C3 — `default = true` on a labelled `ca` block (chosen).** Keeps Terraform's *ergonomics* — one default, others are aliases selected by `host.ca`, hosts omit the selector to get the default — while expressing the default *on a CA* and keeping **every** CA labelled. That preserves the multi-bundle path (every CA, default included, is referenceable by label) and keeps the default co-located with the CA it describes. The only cost is the "at most one `default`" cross-block check, which is trivial. Chosen.

(The earlier "implicit default plus optional labelled CAs" of ADR-010's option B is subsumed here: the default is opt-in and explicit via `default = true`, never implied by block position.)

## Links

- [ADR-010](./010-single-ca-per-config.md) — the single-CA decision this supersedes; its forward-compat sketch is the path taken here.
- [ADR-016](./016-ca-rotation-and-trust-bundles.md) — CA rotation and trust bundles, the primary consumer of multi-CA.
- [ADR-009](./009-host-identifier-vs-cert-name.md) — label-vs-name precedent, applied here to CAs.
- [ADR-007](./007-schema-evolution.md) — schema-evolution policy; this change is additive and needs no schema bump.
- [ADR-002](./002-state-and-artifact-layout.md) — manifest `cas` map and per-host `ca` field.
- [`hcl-schema.md`](../hcl-schema.md) — schema reference and validation rules.
