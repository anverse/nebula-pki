# Homelab example

A small home or hobby mesh: a single overlay split into a dev and a prod
environment, each with its own CA, a handful of cluster nodes, a couple
of admin laptops, and an optional phone or two.

This is the smallest realistic shape for `nebula-pki`. If your needs are
larger or more structured (multiple sites, role-based subnets, per-site
`output_dir`), see [`../business/`](../business/example.md).

## Files

| File | Purpose |
|---|---|
| [`dev.hcl`](./dev.hcl)   | Dev environment — CA `homelab-dev`, host range `172.16.{0,1,2}.0/24`. |
| [`prod.hcl`](./prod.hcl) | Prod environment — CA `homelab-prod`, host range `172.16.{100,110,120}.0/24`. |

Both configs share this directory and write to disjoint subtrees under
`out/`, which is the supported pattern for multi-CA setups
([ADR-010](../../spec/adr/010-single-ca-per-config.md)).

## Address plan

```
172.16.0.0/16                                    overlay (shared by dev and prod)

  dev (homelab-dev CA)
    172.16.0.0/24     admin laptops, phones      laptop_1 = .1, laptop_2 = .2
    172.16.1.0/24     cluster control-plane      node_1..node_5 = .1..5
    172.16.2.0/24     cluster workers            (optional)

  prod (homelab-prod CA)
    172.16.100.0/24   admin laptops, phones      laptop_1 = .1, laptop_2 = .2
    172.16.110.0/24   cluster control-plane      node_1..node_5 = .1..5
    172.16.120.0/24   cluster workers            (optional)
```

The two CAs are signed independently, so a dev cert cannot authenticate
to prod and vice versa, even though the overlay /16 is shared.

## What the configs demonstrate

- Two CAs in one working directory, one per file.
- A single `output_dir` per environment (`out/<env>/cluster/`) that
  a downstream consumer (Terraform, Ansible, ...) can read with no
  extra glue. Hosts opt into it via `output_dir = "out/<env>/cluster"`.
- Default placement for admin laptops (no `output_dir`) ends up in
  `out/<env>/hosts/`.
- `lighthouse` group on every control-plane cert. Which node actually
  runs as a lighthouse is a **runtime** decision in `config.yaml`, not
  a cert property — `nebula-pki` deliberately has no `is_lighthouse`
  concept.
- Sops encryption with an empty block, deferring recipients to
  `.sops.yaml`. Drop in `age = [...]` for inline recipients.

## Running

```sh
# Preview the dev plan — no files written.
nebula-pki -c dev.hcl --dry-run

# Reconcile.
nebula-pki -c dev.hcl
nebula-pki -c prod.hcl
```

Resulting layout (sops backend, default `.enc` suffix):

```
homelab/
  dev.hcl
  prod.hcl
  out/
    dev/
      nebula-pki.json
      ca/
        ca.crt
        ca.key.enc
      cluster/                    # <- consumed by the cluster deploy
        node_1.crt
        node_1.key.enc
        ...
        node_5.crt
        node_5.key.enc
      hosts/                      # <- default location, admin laptops
        laptop_1.crt
        laptop_1.key.enc
        laptop_2.crt
        laptop_2.key.enc
    prod/
      (same shape)
```

Both `nebula-pki.json` manifest files are safe to commit. They hold cert
fingerprints, validity, and artifact paths — no secret material.

## Mobile devices

Phones never give up their private key, so the cert-signing flow for
them is different from a laptop:

1. **On the phone.** In the Nebula app (iOS or Android), tap *Sites → + →
   Create a Site Manually → Generate Key Pair*. The app generates a
   keypair on-device. Tap *Share Public Key* to export only the public
   half — a short text block beginning with
   `-----BEGIN NEBULA X25519 PUBLIC KEY-----`.

2. **On the operator workstation.** Save the exported public key into
   `mobile-pubkeys/<host_label>.pub` in this directory:

   ```sh
   mkdir -p mobile-pubkeys
   pbpaste > mobile-pubkeys/phone_1.pub   # macOS; or write the file manually
   ```

3. **Add an HCL block.** In `dev.hcl` (or `prod.hcl`), uncomment / add:

   ```hcl
   host "phone_1" {
     networks = ["172.16.0.10/16"]      # pick an address inside the admin subnet
     groups   = ["admin", "mobile"]
     in_pub   = "./mobile-pubkeys/phone_1.pub"
   }
   ```

   `in_pub` maps directly to `nebula-cert sign -in-pub`. Because we are
   supplying the public key, `nebula-pki` does NOT generate a private
   key for this host. No `.key` (or `.key.enc`) file is produced — only
   the `.crt`.

4. **Reconcile.**

   ```sh
   nebula-pki -c dev.hcl
   ```

   The cert lands at `out/dev/hosts/phone_1.crt`. The matching private
   key is still on the phone, where it has always been.

5. **Back to the phone.** Send the signed `.crt` and the CA cert
   (`out/dev/ca/ca.crt`) to the phone — AirDrop, signal-to-self, the
   secure-share feature inside the Nebula app, whatever you trust. In
   the app: *Site → Certificate → Import* for the host cert, and
   *Site → CA → Import* for the CA cert.

### Why this fits the threat model

The mobile workflow is the cleanest demonstration of why `nebula-pki`
was designed not to invent its own key transport: there is nothing to
transport. The CA signs a public key handed to it, and the resulting
cert is a public artifact. The only thing that ever needed protection —
the private key — never enters the tool's process or the operator's
machine.

### Rotation

Phones can be rotated independently. Generate a fresh keypair on the
device, export the new public key, overwrite
`mobile-pubkeys/<host>.pub`, re-run `nebula-pki`. The manifest will
show a new fingerprint for that host on the next run.
