# CA rotation and trust bundles

## Status

accepted

## Context

A Nebula CA has a hard expiry — one year by default. When it expires, **every** host certificate it signed becomes invalid at the same instant and the mesh stops handshaking. Certificates cannot be patched to extend this: any edit invalidates the signature. The only safe path across a CA boundary is an **overlap rotation**, and the mechanism Nebula provides for it is the **trust bundle**.

### What a trust bundle is

`pki.ca` in each host's runtime `config.yaml` is not a single CA certificate — it is a **collection** of trusted CAs, PEM-encoded and concatenated into one file (or inlined). From the upstream [`pki.ca` reference](https://nebula.defined.net/docs/config/pki/):

> The `ca` is a collection of one or more certificate authorities this host should trust... concatenated into a single file.

A host accepts a peer's handshake if the peer's certificate is signed by **any** CA in its bundle. With a single CA, the bundle is just `ca.crt`. The bundle matters during rotation, when it transiently holds two CAs.

### The upstream rotation dance

The [Rotating a Certificate Authority](https://nebula.defined.net/docs/guides/rotating-certificate-authority/) guide is four steps:

1. **Generate CA2** with the same network/group/subnet restrictions as CA1.
2. **Distribute the bundle `CA1 + CA2`** to every host's `pki.ca` and reload. Now every host *trusts* both CAs, though all live host certs are still signed by CA1.
3. **Re-sign every host certificate under CA2** and roll them out one at a time. Each re-signed host stays reachable because the whole mesh already trusts CA2.
4. Once every host runs a CA2 cert, **drop CA1** from the bundle and reload.

This is precisely the kind of multi-step, "did I re-sign all of them?" choreography a declarative tool should own. `nebula-pki` already produces the CA and the host certs; rotation is the workflow that most justifies a declarative layer over `nebula-cert`.

### Two distinct axes

The rotation dance only makes sense if the tool separates two things that a naive "one CA" model conflates:

- **Which CA *signs* a given host certificate** — a per-host choice that moves from CA1 to CA2 over the rotation.
- **Which CAs the mesh *trusts*** — the set in the bundle, which holds both CAs during the overlap and one outside it.

A host can be signed by CA2 while the bundle still includes CA1, and vice versa. Modelling these as one value is what makes rotation impossible to express.

## Decision

Rotation is expressed declaratively on top of the multi-CA schema from [ADR-015](./015-multiple-cas-per-config.md). `nebula-pki` automates the **artifact** side of the dance — generating CA2, signing/re-signing hosts under the chosen CA, and emitting the trust bundle. It does **not** push configs or reload daemons; that stays a downstream concern (see Non-goals).

### 1. The trust bundle is an emitted artifact

`nebula-pki` writes a concatenated-PEM trust bundle containing every CA the mesh should currently trust. By default:

```
out/ca/bundle.crt        # PEM of every active (non-archived) CA cert, concatenated
```

Downstream `config.yaml` points `pki.ca` at this file (or inlines its contents). The path is configurable via `storage.trust_bundle_file`. The bundle is a public artifact — it contains only CA **certificates**, never keys — and is always safe to commit.

In the single-CA case the bundle is a one-cert file equal to `ca.crt`; emitting it unconditionally means downstream consumers always have one stable path to point `pki.ca` at, and that path simply gains a second cert during rotation and loses it afterward — no consumer-side change required across the whole rotation.

### 2. Membership: which CAs are in the bundle

In this milestone, membership is **implicit**: the trust bundle contains every CA declared in the file that is not explicitly archived. There is exactly one bundle per config file, and a CA opts *out* of it via `archived = true`.

```hcl
ca "current" {
  name = "mesh-2026"
}

ca "next" {
  name = "mesh-2027"
}
```

Both `current` and `next` are active, so the bundle contains both. Archiving a CA removes it from the bundle on the next run:

```hcl
ca "current" {
  name     = "mesh-2026"
  archived = true            # drops out of the trust bundle
}

ca "next" {
  name = "mesh-2027"
}
```

`archived = true` describes the CA's **operational** state: its certificate is excluded from the emitted bundle and it may no longer sign hosts. Its manifest record is **kept regardless** — archiving never deletes history; the fingerprint and validity window stay recorded for audit and for any downstream blocklist tooling. (Deleting the `ca` block entirely is what eventually drops the record.) `archived` exists so an operator can stage the final rotation step — and review the resulting bundle diff — before deleting the block and, eventually, the key on disk.

#### Why implicit membership now, and the door left open

One implicit bundle per file is the right default: rotation needs exactly one bundle (the set the mesh currently trusts), and "every non-archived CA is in it" is the obvious rule. But it forecloses nothing. If a future need arises to (a) state bundle membership **explicitly** rather than by the archived flag, or (b) emit **multiple** bundles from one config (e.g. distinct trust sets for distinct host populations), it is reachable additively via a named `bundle` block — without breaking the implicit form:

```hcl
# Possible future shape — NOT in this milestone:
bundle "edge" {
  path = "out/ca/edge-bundle.crt"
  cas  = ["current", "next"]      # explicit membership
}

bundle "core" {
  path = "out/ca/core-bundle.crt"
  cas  = ["next"]
}
```

Rules that keep this additive:

- With **no** `bundle` block (the only shape this milestone ships), behaviour is exactly as specified above: one implicit bundle at `storage.trust_bundle_file` containing every non-`archived` CA.
- Introducing one or more `bundle` blocks would switch to explicit membership; the implicit bundle could either remain as the default or be suppressed when any `bundle` block is present (to be decided in that future ADR).
- `archived` and explicit `bundle.cas` are not in conflict: an archived CA is simply ineligible for any bundle and for signing, whether membership is implicit or explicit.

The bar for adding the `bundle` block is a concrete need for multiple trust sets or explicit membership — the same YAGNI discipline [ADR-011](./011-output-blocks-are-directories.md) applies to the `output` block. Until then, implicit membership keeps the schema small. See also [ADR-015](./015-multiple-cas-per-config.md), under which a `bundle.cas` entry would be a label reference exactly like `host.ca`.

### 3. Signing: which CA signs each host

Per [ADR-015](./015-multiple-cas-per-config.md), each host's signing CA is `host.ca`, falling back to whichever CA is marked `default = true`. The rotation flip is therefore moving the default marker from the old CA to the new one:

```hcl
ca "current" {
  name = "mesh-2026"
  # default = true   ← removed
}

ca "next" {
  name    = "mesh-2027"
  default = true      # ← moved here
}
```

On the next run, every host that relied on the default is re-signed under `next` (the re-sign is driven by the change in `ca_fingerprint`; see the idempotency rule in [ADR-002](./002-state-and-artifact-layout.md)). Hosts pinned with an explicit `host.ca` are unaffected until their pin changes — useful for canarying the new CA on a few hosts (set `ca = "next"` on them) before moving the default.

### The full rotation, declaratively

| Upstream step | `nebula.hcl` edit | What `nebula-pki` does on the next run |
|---|---|---|
| 1. Generate CA2 | Add `ca "next" {}` | Generates `next`'s key/cert; records it in `cas`. |
| 2. Distribute `CA1+CA2` | (none — automatic) | Bundle now contains both; operator ships `out/ca/bundle.crt` and reloads. |
| 3. Re-sign hosts onto CA2 | move `default = true` to `next` (or set `ca = "next"` per host to canary) | Re-signs affected hosts under `next`; fans out new certs. |
| 4. Drop CA1 | `archived = true` on `current` (later delete the block) | Bundle drops `current`; operator ships the slimmer bundle and reloads. |

The operator still performs the two **distribution + reload** actions (steps 2 and 4 require touching every host's running config — inherently outside this tool). Everything between — generating, signing, re-signing, bundling, and tracking progress in the manifest — is `edit HCL + re-run`.

### Rotation progress is observable

The manifest records each CA in `cas` (fingerprint, validity, `archived` flag) and each host's signing CA. Downstream tooling — or a future `nebula-pki show` — can answer "how many hosts are still on `current`?" by counting host records whose `ca` is `current`. This is the signal that tells an operator when step 4 is safe.

## Non-goals (unchanged by this ADR)

- **No config push, no daemon reload.** `nebula-pki` writes files. Distributing `bundle.crt` and the new host certs to running hosts, and issuing the reload (`SIGHUP`/`systemctl restart`), remain the job of the downstream config-management pipeline. This preserves the [spec non-goal](../readme.md#non-goals) "Distribution to hosts."
- **No automatic CA key generation onto an untrusted machine beyond what generate mode already does.** Generate mode writes the CA key to disk as today; protecting it is the operator's responsibility (and `ca.encrypt`, once implemented, applies).
- **No revocation.** [ADR-004](./004-revocation-strategy.md) stands. Archiving a CA removes trust in *that CA's* signatures by dropping it from the bundle; blocklisting an individual still-valid host cert remains downstream.

## Consequences

### Positive

- The single most error-prone Nebula operational task becomes a reviewable diff plus a re-run.
- The bundle path is stable across the entire rotation, so downstream `pki.ca` configuration does not change shape mid-rotation.
- `archived` gives a safe, reversible staging point before key deletion — the bundle change can be reviewed and shipped independently of destroying old key material.
- The same dual-trust machinery is the substrate for the v1→v2 / IPv6 certificate migration (`pki.initiating_version`), where hosts likewise carry two certs during the transition. This ADR does not build that migration, but multi-CA + bundle emission do not preclude it and likely accelerate it.

### Negative

- Operators can still foot-gun the *ordering*: moving the `default` to `next` (step 3) before shipping the `CA1+CA2` bundle (step 2) will partition the mesh. The tool emits the correct artifacts but cannot enforce the *distribution* order, because it does not push. `--dry-run` showing "N hosts will be re-signed under `next`" plus documentation are the mitigations; a future guard could warn when the default (or a `host.ca`) names a CA whose cert is newer than the last-emitted bundle the manifest recorded.
- Generate mode for a second CA means a second CA private key on disk on the signing workstation. This is inherent to rotating without an HSM and is the same exposure as the first CA key.
- Bundle emission adds a small artifact and manifest surface (`trust_bundle`).

## Considered alternatives

### A. A `rotate` subcommand that drives the steps imperatively

A stateful `nebula-pki rotate start|advance|finish`. Rejected: it puts rotation state in the tool's commands rather than in the reviewable `nebula.hcl`, breaking the "config is the source of truth, re-run to reconcile" model that the rest of the tool follows. Expressing rotation as ordinary edits to declared CAs keeps one mental model.

### B. Tool pushes the bundle and reloads hosts

Rejected: violates the "Distribution to hosts" non-goal and would require the tool to grow SSH/transport and host inventory — a different product. Downstream config management already owns this.

### C. Emit the bundle only when more than one CA is active

Rejected: emitting it unconditionally gives downstream `pki.ca` a single stable path that is correct before, during, and after rotation. Conditional emission would force a consumer-side path change at the exact moment correctness matters most.

## Links

- [ADR-015](./015-multiple-cas-per-config.md) — multi-CA schema this builds on (`ca` labels, `host.ca`, `ca.default`).
- [ADR-002](./002-state-and-artifact-layout.md) — manifest `cas` map, `trust_bundle` record, and the re-sign idempotency rule.
- [ADR-004](./004-revocation-strategy.md) — revocation/blocklist remains downstream; unaffected.
- [ADR-017](./017-host-renewal-threshold.md) — `renew_before`, which makes the re-sign step self-healing rather than manual.
- Upstream: [Rotating a Certificate Authority](https://nebula.defined.net/docs/guides/rotating-certificate-authority/), [`pki.ca` config](https://nebula.defined.net/docs/config/pki/).
