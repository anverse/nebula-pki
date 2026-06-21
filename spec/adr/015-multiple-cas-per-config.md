# Multiple CAs per configuration file

## Status

accepted — supersedes [ADR-010](./010-single-ca-per-config.md)

Amended in v0.0.8: the unlabelled `ca {}` form has been removed; all CAs must be labelled. See **Amendment: labels are always required** below.

## Context

[ADR-010](./010-single-ca-per-config.md) restricted a configuration file to exactly one `ca` block and deferred multi-CA support as YAGNI. That call was correct for the early milestones: it kept the manifest single-rooted, removed a class of validation rules, and the "one HCL file per CA" workaround covered the only motivating case at the time (isolated `dev`/`staging`/`prod` environments).

The constraint stops being correct the moment **CA rotation** enters scope. Nebula CAs expire — one year by default — and the only safe way across that boundary is an **overlap window** in which two CAs are trusted simultaneously while host certificates are re-signed from the old CA onto the new one (see the upstream [Rotating a Certificate Authority](https://nebula.defined.net/docs/guides/rotating-certificate-authority/) guide, and [ADR-016](./016-ca-rotation-and-trust-bundles.md)). Rotation is therefore not an exotic feature; it is the one operational task every long-lived mesh must perform, and it is intrinsically a **two-CA** state.

The "two HCL files" workaround does not model rotation well:

- The two CAs are not independent environments; they are the *same* mesh in transition. Splitting them across files means no single `nebula-pki` run sees both, so the tool cannot emit a combined trust bundle, cannot decide which CA should sign a given host, and cannot report rotation progress.
- The host list is shared between old and new CA. Duplicating it across two files invites drift exactly when correctness matters most.

## Decision

A configuration file may declare **one or more** labelled CAs. The `ca "<label>" { ... }` form is the only accepted form. An unlabelled `ca { ... }` block is a parse error.

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

- **Cardinality.** Zero `ca` blocks is an error. Every `ca` block must have exactly one label. An unlabelled `ca {}` block is an error.
- **CA labels** follow the same identifier rules as host labels (`^[A-Za-z_][A-Za-z0-9_-]*$`) and must be unique within the file.
- **`ca.default`** is an optional boolean on a `ca` block marking it the default signing CA. **At most one** CA may set `default = true`; more than one is a validation error.
- **`host.ca`** selects the signing CA by label. It is:
  - **optional** when the file has exactly one CA — there is nothing to disambiguate, so it may be omitted (or set explicitly, which is accepted but redundant);
  - **optional** when a CA is marked `default = true` — omitting `host.ca` uses the default, setting it selects a non-default CA (an "alias");
  - **required** when the file has more than one CA **and** none is marked `default` — every host must then name its CA explicitly.

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

## Why now

Doing this **before the v0.1 freeze** is deliberate. v0.1 freezes the HCL surface for the 0.1.x line. Multi-CA is foundational — rotation, trust bundles, and the manifest's CA shape all build on it. Introducing it after v0.1 would force a breaking schema change (the `nebula_pki { schema = 2 }` mechanism of [ADR-007](./007-schema-evolution.md)) for something we can see coming now.

## Amendment: labels are always required

**Adopted in v0.0.8.** The original decision allowed an unlabelled `ca {}` as the "common case" for single-CA files, with labelled `ca "<label>" {}` as an opt-in for multi-CA. After implementation, this two-shape approach was dropped in favour of always requiring a label. The reasons:

1. **Rotation is not optional.** Nebula enforces a CA duration (`8760h` by default). Every CA will eventually expire. Rotation ([ADR-016](./016-ca-rotation-and-trust-bundles.md)) is intrinsically a two-CA state. The "single CA now, add a second later" path is the norm, not the exception. Asking operators to add a label when they first write the config — rather than requiring a label-addition during the pressured rotation window — is the right ergonomic.

2. **The unlabelled form was a maintenance tax with no benefit.** Keeping both shapes required dual parsing paths (two raw schema structs, a body-shape-detection pass, separate decode branches), dual validation rule sets (rules about what is and is not allowed *on* the unlabelled form), and kept `cas` out of the manifest for unlabelled configs. Every downstream milestone (rotation, trust bundles) had to branch on "is this a single unlabelled CA?". None of that complexity earned anything: an operator starting with one CA writes `ca "mesh" {}` just as easily as `ca {}`.

3. **The manifest is simpler.** With always-labelled CAs, the manifest always uses the `cas` map. No `ca` / `cas` duality to version or document. Downstream consumers (Terraform, scripts) have one stable path.

4. **Validation rules are simpler.** The unlabelled form introduced rules that existed purely to protect the unlabelled form from itself: "forbidden: `default = true` on an unlabelled single CA", "forbidden: `host.ca` in a single-CA file". With always-labelled, those rules disappear.

5. **This is a pre-v0.1 release; breaking changes are expected.** The HCL surface is not frozen until v0.1.0. Any operator who wrote an unlabelled `ca {}` block adds a label; the rest of the config is unchanged.

The unlabelled `ca {}` block is now a **parse error** with a clear message:
```
ca: block requires a label; use ca "<label>" { ... }
```

## Manifest impact

The manifest uses a `cas` map keyed by CA label (always). There is no single-CA `ca` object. Per-host records carry a `ca` field naming the signing CA label; the existing `ca_fingerprint` already pins the exact cert. Full schema in [ADR-002](./002-state-and-artifact-layout.md).

## Consequences

### Positive

- Rotation becomes expressible declaratively (ADR-016): two CAs in one file, one mesh, one run, one manifest, one trust bundle.
- The host list lives in exactly one place during rotation; no cross-file duplication.
- Environment isolation (`dev`/`prod`) still works the same way — separate files — for operators who prefer it.
- The manifest `cas` shape is uniform: every manifest has a `cas` map, regardless of how many CAs are declared.
- Parsing, validation, and plan/apply code have one code path for CAs, not two. Fewer branches means fewer bugs and simpler tests.

### Negative

- Operators upgrading from ≤v0.0.7 must add a label to their `ca` block. The error message makes the fix obvious.
- Two name-like axes on CAs (the label vs. `ca.name`) mirror the host label-vs-name split of [ADR-009](./009-host-identifier-vs-cert-name.md); the same reasoning and the same potential for confusion apply.

## Considered alternatives

### A. Keep ADR-010; rotation via two files plus a concatenation step

Rejected. A standalone "concatenate these two CA certs" step can produce a bundle, but it cannot decide which CA signs which host, cannot keep the host list single-sourced, and cannot report rotation progress in one manifest. It pushes the coordination back onto the operator, which is the toil the tool exists to remove.

### B. A dedicated rotation primitive instead of general multi-CA

A purpose-built CA shape with a baked-in "previous/next CA" pointer, narrower than general multi-CA. Rejected: it is a less general answer to a more general need (staging a second CA, signing different hosts under different CAs, the v1→v2 migration) and it would itself need replacing the first time a second legitimate multi-CA use appears. General labelled CAs cost little more and subsume the rotation case.

### C. Keep the unlabelled form alongside labelled

The original v0.0.8 plan preserved `ca {}` as the single-CA shortcut. Rejected after implementation planning: see **Amendment: labels are always required** above.

### D. How the default signing CA is expressed

**D1 — root-level `default_ca = "label"`.** Rejected: detaches the decision from the CA block, duplicates the label as a free-floating string.

**D2 — unlabelled `ca {}` is the default.** Rejected: requires the default CA to be unlabelled, which precludes referencing it in `bundle.cas = [...]` by label.

**D3 — `default = true` on a labelled `ca` block (chosen).** Every CA is labelled and referenceable. The default is co-located with its CA block. The only cost is the "at most one `default`" cross-block check.

## Links

- [ADR-010](./010-single-ca-per-config.md) — the single-CA decision this supersedes.
- [ADR-016](./016-ca-rotation-and-trust-bundles.md) — CA rotation and trust bundles, the primary consumer of multi-CA.
- [ADR-009](./009-host-identifier-vs-cert-name.md) — label-vs-name precedent, applied here to CAs.
- [ADR-007](./007-schema-evolution.md) — schema-evolution policy; this change is additive and needs no schema bump.
- [ADR-002](./002-state-and-artifact-layout.md) — manifest `cas` map and per-host `ca` field.
- [`hcl-schema.md`](../hcl-schema.md) — schema reference and validation rules.
