# `in_pub` air-gapped signing, config-only

## Status

accepted

## Context

The most security-sensitive Nebula pattern is **"the private key never leaves the device."** The device generates its own keypair, keeps the private key sealed locally, and exports only the **public** key. The CA operator signs that public key and hands back a certificate. The operator never possesses — and therefore can never leak — the host's private key.

Real cases where this matters:

- **Mobile (iOS / Android Mobile Nebula).** The app generates the keypair on-device and stores the private key in the platform keystore (Secure Enclave / Keystore). It is non-exportable by design; you can only get a `.pub` out. This is the canonical case and the one motivating this ADR.
- **HSM / TPM / Secure Enclave–backed host keys** on servers or laptops, where the key is hardware-bound and non-exportable.
- **Separation of duties / compliance.** The CA operator is required *not* to hold host private keys, so a compromise of the signing workstation cannot impersonate hosts.
- **Untrusted or shared CA workstation.** Even momentarily writing plaintext host keys on the signing machine is unacceptable.

In all of these, the artifact that reaches the CA is a PEM **public key** file (`.pub`). The corresponding upstream flow is two commands on two different machines: `nebula-cert keygen` on the **device** to produce `device.key` + `device.pub`, then `nebula-cert sign -in-pub device.pub` on the **CA host** to produce `device.crt` (see [Signing a Certificate Without a Private Key](https://nebula.defined.net/docs/guides/sign-certificates-with-public-keys/)).

The `host.in_pub` field already exists in the schema ([`hcl-schema.md`](../hcl-schema.md)) but is currently inert. This ADR specifies its behaviour and, importantly, settles a design question: does `nebula-pki` need its own `keygen` subcommand to support this flow?

## Decision

`in_pub` is supported **entirely through configuration and the filesystem. `nebula-pki` does not gain a `keygen` subcommand.**

### Why no `keygen` subcommand

`nebula-cert keygen` exists because nebula-cert is a **device-side, stateless** tool: the phone or laptop runs it locally to make its own keypair, on a machine that is *not* where the CA or the `nebula.hcl` lives. That is the correct place for key generation in this pattern — on the device that will guard the key.

`nebula-pki` is the **CA-side, declarative** tool. Its `nebula.hcl` and its run happen on the signing workstation. If `nebula-pki` generated the host's keypair, the private key would exist on the CA workstation — which is exactly what the air-gapped pattern forbids. So a `keygen` subcommand in `nebula-pki` would, for the use case that motivates the feature, be **actively wrong**: it would defeat the property the operator is trying to preserve.

The keypair is therefore produced by whatever owns the device:

- Mobile Nebula generates it on-device and exports the `.pub`.
- A server/laptop runs `nebula-cert keygen` *there* (a device concern, not nebula-pki's).

`nebula-pki`'s only job is the **signing** half, and that needs nothing but the public key on disk and a line of config:

```hcl
host "alice_phone" {
  networks = ["10.42.5.20/16"]
  groups   = ["mobile"]
  in_pub   = "./inbox/alice_phone.pub"   # the device's exported public key
}
```

The operator obtains `alice_phone.pub` out of band (the device exports it; it is non-secret) and places it where the config points. No subcommand, no imperative step inside nebula-pki.

### Signing behaviour

When `in_pub` is set, on reconcile `nebula-pki`:

1. Reads the PEM public key at the given path (relative to the config file, like other paths).
2. Verifies its **curve matches the signing CA's curve**. Upstream `nebula-cert sign` rejects a curve mismatch (`curve of in-pub does not match ca`); `nebula-pki` performs the same check at validation/reconcile time and fails with a clear message.
3. Signs a certificate for the host's `name`, `networks`, `groups`, `unsafe_networks`, and resolved `duration`, under the host's signing CA ([ADR-015](./015-multiple-cas-per-config.md)).
4. Writes **only** the certificate (`<name>.crt`) to the host's configured `output_dir` (or the default placement), like any other cert.
5. Writes **no** private key, and applies **no** encryption — there is no private material in this flow, so the encryption backends ([ADR-006](./006-storage-backend-extensibility.md)) and the `.key` suffix logic simply do not apply to this host.

### Mutual exclusions and provenance

- `in_pub` is mutually exclusive with `host.out_key` — there is no key to write, so naming a key output path is a configuration error.
- `in_pub` composes normally with `output_dir` and `host.out_crt` (custom output dir / cert path component).
- The manifest records the host with an `in_pub: true` provenance marker (or an `in_pub` source-path field) and **omits the key artifact**: each `artifacts` entry has a `cert_path` but no `key_path`. Downstream tooling reading the manifest can tell at a glance which hosts are self-keyed.

### Renewal

A host signed via `in_pub` renews ([ADR-017](./017-host-renewal-threshold.md)) by re-signing the **same** public key — the cert's `not_after` moves forward, the key never changes. This is the correct behaviour for hardware-bound keys, where the key *cannot* change. It is also the one renewal case that does not produce new key material, which is a feature, not a limitation.

## What this does not provide

- **nebula-pki will not generate the device keypair.** By design (see above). The device, or `nebula-cert keygen` on the device, does that. The readme/agents.md must not claim "no nebula-cert needed" for this flow: the device side still uses `nebula-cert keygen` (or the mobile app's built-in generation).
- **No transport of the `.pub` to the CA host.** The operator moves the public key into place (it is non-secret; email, a PR, a shared bucket, or a QR scan all work). The tool reads it from the path given.

A convenience helper that mints a throwaway keypair *on the CA box* for testing is explicitly **out of scope**: it would model the insecure pattern (key on the CA host) and there is already a tool for it (`nebula-cert keygen`). If a test fixture needs a keypair, tests generate one directly via the `slackhq/nebula/cert` library, not via a shipped subcommand.

## Consequences

### Positive

- The "private key never leaves the device" pattern — mobile, HSM, separation-of-duties — is fully supported with config only. No new command surface, consistent with the small CLI of [ADR-008](./008-cli-surface.md).
- The schema field that already exists (`in_pub`) finally does something, with semantics matching upstream `nebula-cert sign -in-pub`.
- The tool's trust boundary improves: for `in_pub` hosts, the signing workstation never holds the host private key, so the manifest and `out/` carry strictly less secret material.
- Renewal of hardware-bound keys is correct by construction (cert refreshes, key stays put).

### Negative

- A two-machine, two-tool flow (device runs `nebula-cert keygen`; CA host runs `nebula-pki`) is inherent and slightly less turnkey than "nebula-pki does everything." This is the unavoidable cost of keeping the private key off the CA host, and the right trade.
- Operators must get the `.pub` to the CA host themselves. Mitigated by it being non-secret; documentation will show the mobile-app export and the `nebula-cert keygen` paths.
- Per-host divergence in output shape (cert-only vs. cert+key) adds a small amount of manifest and apply-path conditionality.

## Considered alternatives

### A. Add a `nebula-pki keygen` subcommand mirroring `nebula-cert keygen`

Rejected. For the motivating use case it is wrong: running it on the CA host puts the private key on the CA host, defeating the pattern; running it on the device is just `nebula-cert keygen` by another name (and the device already has that, or generates in-app). It would add CLI surface that is at best redundant and at worst a security foot-gun.

### B. Generate the keypair in nebula-pki and "promise" to delete the private key after handing it to the operator

Rejected. Any window in which the private key exists on the CA workstation breaks the guarantee, and "we delete it afterward" is exactly the weak posture the air-gapped pattern exists to avoid. The key must be born on the device.

### C. Leave `in_pub` unimplemented and tell operators to run raw `nebula-cert sign`

Rejected. `in_pub` hosts would then be invisible to the declarative config and absent from the manifest — no single view of the Nebula network, no idempotency, no fan-out for their certs. Wiring the existing field through is cheap and keeps these hosts first-class.

## Links

- [ADR-015](./015-multiple-cas-per-config.md) — signing CA selection (`host.ca`, or the CA marked `default = true`) applies to `in_pub` hosts too.
- [ADR-017](./017-host-renewal-threshold.md) — renewal re-signs the same public key for `in_pub` hosts.
- [ADR-006](./006-storage-backend-extensibility.md) — encryption backends; they do not apply to `in_pub` hosts (no private key).
- [ADR-008](./008-cli-surface.md) — small CLI surface; this ADR keeps it small by adding no subcommand.
- Upstream: [Signing a Certificate Without a Private Key](https://nebula.defined.net/docs/guides/sign-certificates-with-public-keys/).
