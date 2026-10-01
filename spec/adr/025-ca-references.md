# Terraform-style CA references (`ca.<label>`)

* Status: accepted
* Deciders: fw
* Date: 2026-08-22

## Context and Problem Statement

A `cert` block ([ADR-024](./024-rename-host-to-cert.md)) names its signing CA by the CA's
label as a plain string: `cert "app_01" { ca = "next" }`. Plain strings are a weak substrate:
they are indistinguishable from any other string value, tooling cannot reliably find or
rewrite them, and a typo is only caught by a post-decode label lookup with a generic error.

Terraform solved the same problem with attribute traversals: `aws_instance.web` is syntax,
not a string. HCL exposes the same machinery.

## Decision

### Reference syntax

Every field whose value designates a declared CA takes a **traversal** of the form
`ca.<label>`, where `<label>` is the label of a `ca` block in the same file:

```hcl
ca "current" { name = "mesh-2026" }
ca "next"    { name = "mesh-2027" }

cert "app_01" {
  networks = ["10.42.1.10/16"]
  ca       = ca.next            # reference, not a string
}
```

The first field to use it is `cert.ca` (hard switch, see below).

### Hard switch for `cert.ca`

Only references are accepted in `cert.ca` from the release that ships this ADR. There is no
dual-accept window and no migration path: a quoted string is rejected like any other
expression that is not a `ca.<label>` traversal, with the same validation error:

```
cert "app_01": ca must be a CA reference of the form ca.<label>
```

Rationale: the tool is still experimental ([ADR-007](./007-schema-evolution.md) 2026-09-26
amendment), so breaking changes ship without migration aids; a dual-accept window would mean
two syntaxes in every example and test with no user base that benefits.

### Implementation

No evaluation context is introduced. The field is decoded as a raw `hcl.Expression`
(supported natively by `gohcl`), then:

1. `hcl.ExprList(expr)` splits list fields into element expressions (for any list-valued
   reference field).
2. `hcl.AbsTraversalForExpr(expr)` extracts the traversal; anything that is not a bare
   traversal (a quoted string, a function call, an index) is rejected with the validation
   error above.
3. The traversal must have exactly two steps: root `ca`, then one attribute step — the label.
   Any other root or shape is an error (`unknown reference root "cert"; only ca.<label> references are supported`).
4. The label is resolved against declared `ca` blocks post-decode, exactly as string labels
   are resolved today; an unresolved label is an error carrying the expression's source range.

This is the same technique Terraform uses for `depends_on`. It is deliberately **not** an
eval context: `ca.next` never evaluates to a value, so it cannot leak into string
interpolation, and the reference remains a distinct syntactic object that `hclwrite`-based
tooling can find, generate, and rewrite mechanically.

## Naming: scalar `cert.ca` keeps the bare token; list fields take a plural

A reference names the declared block by its **block-type keyword** as the root (`ca.<label>`),
mirroring Terraform (`<resource_type>.<name>`). References are always *dotted* (`ca.<label>`),
so they stay syntactically distinct from the bare `ca` block keyword and can be found and
rewritten mechanically regardless of the attribute names around them.

The **scalar** signing field keeps the natural name — `cert.ca = ca.next` reads as "this
cert's CA is `next`". The token `ca` does appear on both sides, but for a single value it
reads cleanly and matches the operator's mental model ("which CA signs this cert"), so the
bare name is retained.

The tension only bites for a **list** field. A list attribute should be *plural* (Terraform
convention), and a singular `ca` holding a list reads wrong — `ca = [ca.current, ca.next]`
is "ca equals a list of cas", where the singular attribute name fights the list value and
the root token repeats. So list-of-reference fields take a legible plural rather than bare
`ca`; see the `ca_refs` choice in [ADR-026](./026-trust-bundle-block.md). **Arity is the
line**: scalar keeps `ca`, list takes a plural. (A future HCL eval context, if ever added,
is a further minor reason to keep list membership off the bare `ca` token.)

## What this enables later (non-goals now)

- Autofill: a future `nebula-pki` capability (or editor tooling) can enumerate `ca` blocks
  and write reference tokens into a members list mechanically.
- Renames: renaming a CA label becomes a mechanical find-and-replace of traversals rather
  than a grep for ambiguous strings.
- Additional reference sites reuse this exact syntax — the next is the trust-bundle members
  list in [ADR-026](./026-trust-bundle-block.md).
- Additional reference roots (e.g. `cert.<label>`) fit the same decoder if ever needed.

None of these ship with this ADR.

## Consequences

### Positive

- References are syntax, not strings: typos in the root are parse errors, unresolved labels
  carry precise source ranges, and tooling can manipulate them safely.
- One convention wherever a CA is referenced; examples and documentation teach a single form.
- Zero new evaluation machinery; the decoder change is contained in `internal/config`
  (~40–60 lines plus validation).

### Negative

- **Breaking change, no migration path**: existing configs using `ca = "next"` fail to
  parse until edited. Accepted under the ADR-007 experimental-stage amendment.
- HCL attribute-vs-block ambiguity requires `cert.ca` to move from `*string` to
  `hcl.Expression` in the raw decode struct; unit tests covering the raw schema shape need
  updating.

## Links

- [ADR-024](./024-rename-host-to-cert.md) — the `cert` block whose `ca` field uses this syntax.
- [ADR-015](./015-multiple-cas-per-config.md) — labelled `ca` blocks and `cert.ca` (string form, superseded by this ADR for the syntax).
- [ADR-026](./026-trust-bundle-block.md) — next iteration; its `ca_refs` members list reuses this syntax (and the reserved-root convention).
- [ADR-007](./007-schema-evolution.md) — breaking-change policy; see the experimental-stage amendment.
- Upstream prior art: Terraform `depends_on` traversal decoding (`hcl.AbsTraversalForExpr`).
