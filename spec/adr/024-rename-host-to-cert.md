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
  ca       = "next"                    # signing CA label (string form; see ADR-025)
}
```

The name was chosen because certs are applied to hosts. But `nebula-pki` does exactly one
thing per block — issue a signed certificate (plus its key). It does **not** generate a
node's Nebula daemon config. Naming the block after a *host* over-claims the tool's scope
and collides with how Nebula itself uses the word "host". This ADR renames the block to
`cert` (`cert.name`, `cert.networks`, `cert.ca`, `cert.groups`, `cert.output_dir`,
`cert.in_pub`, …).

## Decision

Rename the block to **`cert`**. This is a **pre-1.0 hard-switch breaking rename** with no
new behaviour: `host` becomes a parse error naming the rewrite, per the
[ADR-007](./007-schema-evolution.md) pre-1.0 amendment. It ships as **its own release,
first** in the schema-change sequence (see "Release sequencing").

```hcl
cert "app_01" {
  name     = "app-01.mesh.internal"
  networks = ["10.42.1.10/16"]
  ca       = "next"
}
```

(The `ca` field still takes a string label at this point; it becomes a `ca.<label>`
reference in [ADR-025](./025-ca-references.md), which ships next.)

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
Mitigation is house style anyway: the parse error on `host` names the rewrite, plus one docs
line ("one `cert` block per node"). That turns a one-time "huh" into a one-time lesson that
*reinforces* the scope boundary — a net positive, not a lingering tax.

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

- [ADR-009](./009-host-identifier-vs-cert-name.md) — reframe "host identifier vs certificate
  name" as "cert block label (HCL identifier) vs cert CN (`name`)". The character-rule and
  rate-of-change rationale is unchanged; only the narrative (the label is now the cert's
  local handle, not a host's).
- [ADR-011](./011-output-blocks-are-directories.md), [ADR-020](./020-output-dir-per-host.md)
  — `host.output_dir`/`out_crt`/`out_key` wording and the per-node directory framing.
- [ADR-015](./015-multiple-cas-per-config.md) — `host.ca` selection wording.
- [ADR-018](./018-in-pub-air-gapped-signing.md) — `host.in_pub`.
- [ADR-002](./002-state-and-artifact-layout.md), [ADR-016](./016-ca-rotation-and-trust-bundles.md)
  — `host.ca` mentions in prose.
- `spec/hcl-schema.md` + `spec/hcl-schema.formal.json` — block name and every field path.
- `internal/config` — the `host` block decode (`rawHost`/`Host`), validation messages. The
  manifest per-cert key semantics are unchanged: the block **label** stays the manifest key.
- `readme.md` and every example/testdata `.txtar` using a `host` block.

## Consequences

### Positive

- The keyword encodes the tool's scope boundary permanently: `nebula-pki` deals in certs,
  not node configs. The "does this touch my daemon config?" question stops recurring.
- Aligns the config with `nebula-cert` and `pki.cert`, shortening the mental bridge for
  users at every level.
- `cert.name` reads consistently ("the certificate's name" = its CN).

### Negative

- **Breaking**: every existing `host` block must be rewritten to `cert` (parse error names
  the rewrite). Accepted per the ADR-007 pre-1.0 amendment.
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

- [ADR-009](./009-host-identifier-vs-cert-name.md) — the label-vs-CN split, reframed by this rename.
- [ADR-007](./007-schema-evolution.md) — pre-1.0 breaking-change amendment.
- [ADR-025](./025-ca-references.md) — next iteration; changes `cert.ca` to a `ca.<label>` reference.
- [ADR-026](./026-trust-bundle-block.md) — later iteration; the explicit trust-bundle block, written against `cert`.
- [Milestone v0.2](../milestones/v0.2.md) — where this rename is scheduled (first of the schema iterations).
