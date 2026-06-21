# Business example

A multi-site corporate mesh on `10.0.0.0/8`: one CA, three sites
(on-prem HQ + two AWS regions), each location's deploy pipeline reads
from its own `output_dir`.

This is the "yes, it scales beyond a homelab" example. It is *not* a
benchmark — `nebula-pki` is still a hand-written-HCL tool aimed at the
dozens-of-hosts range. Configs are reviewed in PRs and a diff per host
is a feature, not a problem at this scale. For a smaller setup see
[`../homelab/`](../homelab/example.md).

## Files

| File | Purpose |
|---|---|
| [`nebula.hcl`](./nebula.hcl) | Single CA, three sites, per-site output directories. |

## Address plan

```
10.0.0.0/8         overlay (CA networks)

  10.10.0.0/16     HQ — on-prem, Frankfurt
    10.10.0.0/24     lighthouses, admin workstations
    10.10.1.0/24     app servers
    10.10.2.0/24     databases
    10.10.9.0/24     edge routers (route 192.168.10.0/24 office LAN)

  10.20.0.0/16     eu-west — AWS eu-west-1
    10.20.0.0/24     lighthouses
    10.20.1.0/24     app servers
    10.20.2.0/24     CI / build workers

  10.30.0.0/16     us-east — AWS us-east-1
    10.30.0.0/24     lighthouses
    10.30.1.0/24     app servers
```

A single CA (`acme-mesh`) signs every host. All hosts can authenticate
to each other; segmentation between sites and roles is enforced at
runtime via Nebula firewall rules that match on the `groups` carried by
each cert.

## What the config demonstrates

- **One CA, many sites.** A single trust root with per-site `output_dir`.
- **`ca.networks` and `ca.groups` as guard rails.** Subordinate certs
  can only declare addresses inside `10.0.0.0/8` and groups from the
  allow-list. Catches typos and out-of-band hosts at config-parse time
  rather than after deploy.
- **`unsafe_networks` for office bridging.** The HQ edge router carries
  `192.168.10.0/24` so overlay peers can reach the office LAN through
  it. The CA's own `unsafe_networks` field whitelists which subnets are
  allowed to appear on subordinate certs.
- **Per-site `output_dir` as deploy target.** Each site's deploy
  pipeline reads from `out/sites/<site>/`. Adding a fourth site means
  setting `output_dir = "out/sites/<site>"` on the new hosts.
- **Default placement for non-shipped hosts.** Admin workstations have
  no `output_dir`; their material ends up under
  `out/hosts/<name>.{crt,key.enc}` and stays on the operator
  workstation.
- **Sops backend deferring to `.sops.yaml`.** Empty `encryption "sops"
  {}` block — recipients live next to the rest of the org's secrets
  configuration.

## Running

```sh
# Preview the plan — no files written.
nebula-pki --dry-run

# Reconcile.
nebula-pki
```

Resulting layout (sops backend, default `.enc` suffix):

```
business/
  nebula.hcl
  out/
    nebula-pki.json
    ca/
      acme-mesh.crt
      acme-mesh.key.enc
    sites/
      hq/
        lh_hq_1.crt        + .key.enc
        lh_hq_2.crt        + .key.enc
        app_hq_1.crt       + .key.enc
        app_hq_2.crt       + .key.enc
        app_hq_3.crt       + .key.enc
        db_hq_primary.crt  + .key.enc
        db_hq_replica.crt  + .key.enc
        router_hq.crt      + .key.enc
      eu-west/
        lh_euw_1.crt       + .key.enc
        app_euw_1..3.crt   + .key.enc
        ci_euw_1..2.crt    + .key.enc
      us-east/
        lh_use_1.crt       + .key.enc
        app_use_1..2.crt   + .key.enc
    hosts/
      admin_1.crt          + .key.enc
      admin_2.crt          + .key.enc
```

The `nebula-pki.json` manifest is safe to commit. It holds cert
fingerprints, validity, and artifact paths — no secret material.

## Adding a host

1. Pick a free address inside the right site's `/16`.
2. Add a `host` block with `output_dir = "out/sites/<site>"` for the
   right site (omit `output_dir` if the host shouldn't ship with the
   site deploy).
3. Run `nebula-pki --dry-run` to confirm the plan, then
   `nebula-pki` to reconcile.
4. The PR diff is one host block. Reviewers see exactly what changes
   on the mesh.

## Adding a site

1. Pick an unused `/16` inside `10.0.0.0/8`.
2. Add an entry to `ca.groups` if the site warrants its own group
   (e.g. `"ap_south"`).
3. Add `host` blocks for that site's lighthouses, app servers, etc.,
   each with `output_dir = "out/sites/<site>"`.

## What this example deliberately does NOT do

- It does not render `config.yaml`. Lighthouse selection, firewall
  rules, blocklist, and runtime tuning live in the downstream deploy
  pipeline.
- It does not ship certs to hosts. Terraform's `file()` reading from
  `out/sites/<site>/` (or any equivalent) handles distribution.
- It does not split into dev/staging/prod. For multiple environments,
  use one HCL file per environment in the same directory — see the
  homelab example or [ADR-010](../../spec/adr/010-single-ca-per-config.md).
