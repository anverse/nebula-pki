# Business example — multi-site corporate Nebula network on 10.0.0.0/8.
#
# One CA, three sites, each with its own output_dir so the relevant
# deploy target (Terraform / Ansible) reads from its own directory.
#
# This example is meant to show "yes, this scales beyond a homelab",
# but the tool is still aimed at the dozens-of-nodes range, not
# thousands. The HCL is written by hand and reviewed in PRs; that's
# the whole point of the declarative rewrite.
#
# Address plan:
#   10.0.0.0/8        overlay
#
#   10.10.0.0/16      HQ (on-prem, Frankfurt)
#     10.10.0.0/24      lighthouses, admin workstations
#     10.10.1.0/24      app servers
#     10.10.2.0/24      databases
#     10.10.9.0/24      edge routers (route 192.168.10.0/24 office LAN)
#
#   10.20.0.0/16      eu-west (AWS eu-west-1)
#     10.20.0.0/24      lighthouses
#     10.20.1.0/24      app servers
#     10.20.2.0/24      CI / build workers
#
#   10.30.0.0/16      us-east (AWS us-east-1)
#     10.30.0.0/24      lighthouses
#     10.30.1.0/24      app servers
#
# See ./example.md for the walkthrough.

ca "acme-mesh" {
  name     = "acme-mesh"
  duration = "43800h"                  # ~5 years
  curve    = "25519"

  # Constrain everything subordinate certs are allowed to claim.
  networks        = ["10.0.0.0/8"]
  unsafe_networks = ["192.168.10.0/24"]

  # Restrict the group vocabulary. Certs may only use groups from this
  # list. Useful when configs are written by multiple teams.
  groups = [
    "lighthouse",
    "admin",
    "app",
    "db",
    "ci",
    "router",
    "hq",
    "eu_west",
    "us_east",
  ]
}

# The trust bundle every node uses as pki.ca. Declared from day one, even
# with a single CA, so pki.ca keeps one stable path when a second CA joins
# during a rotation. Each site directory gets a relative acme.crt symlink.
trust_bundle "acme" {
  ca_refs  = [ca.acme-mesh]
  link_crt = ["out/sites/hq", "out/sites/eu-west", "out/sites/us-east"]
}

storage {
  out_dir = "out"
}

# -----------------------------------------------------------------------------
# Output directories — one per site.
#
# Each cert names its destination via `output_dir`. The per-site deploy
# pipeline (Terraform module, Ansible inventory, ...) reads from these
# directories. Filenames are always <cert.name>.crt and
# <cert.name>.key.enc, derived from the cert label.
#
# Conventions used below:
#   "out/sites/hq"
#   "out/sites/eu-west"
#   "out/sites/us-east"
# -----------------------------------------------------------------------------

# =============================================================================
# HQ — Frankfurt, on-prem
# =============================================================================

# Lighthouses. Two on-prem lighthouses so HQ keeps working if one is down.
cert "lh_hq_1" {
  networks    = ["10.10.0.1/16"]
  groups      = ["lighthouse", "hq"]
  output_dir  = "out/sites/hq"
}

cert "lh_hq_2" {
  networks    = ["10.10.0.2/16"]
  groups      = ["lighthouse", "hq"]
  output_dir  = "out/sites/hq"
}

# Admin workstations (operators). Default placement, no `output_dir`,
# since admin keys don't ship with the site deploy.
cert "admin_1" {
  networks = ["10.10.0.10/16"]
  groups   = ["admin", "hq"]
}

cert "admin_2" {
  networks = ["10.10.0.11/16"]
  groups   = ["admin", "hq"]
}

# App servers.
cert "app_hq_1" {
  networks    = ["10.10.1.1/16"]
  groups      = ["app", "hq"]
  output_dir  = "out/sites/hq"
}

cert "app_hq_2" {
  networks    = ["10.10.1.2/16"]
  groups      = ["app", "hq"]
  output_dir  = "out/sites/hq"
}

cert "app_hq_3" {
  networks    = ["10.10.1.3/16"]
  groups      = ["app", "hq"]
  output_dir  = "out/sites/hq"
}

# Database (primary + replica).
cert "db_hq_primary" {
  networks    = ["10.10.2.1/16"]
  groups      = ["db", "hq"]
  output_dir  = "out/sites/hq"
}

cert "db_hq_replica" {
  networks    = ["10.10.2.2/16"]
  groups      = ["db", "hq"]
  output_dir  = "out/sites/hq"
}

# Edge router. Bridges the overlay onto the HQ office LAN so admins on
# the office Wi-Fi can reach overlay services without each laptop
# joining the Nebula network directly. `unsafe_networks` advertises the route;
# Nebula's firewall on each peer decides whether to honour traffic to
# 192.168.10.0/24.
cert "router_hq" {
  networks        = ["10.10.9.1/16"]
  unsafe_networks = ["192.168.10.0/24"]
  groups          = ["router", "hq"]
  output_dir      = "out/sites/hq"
}

# =============================================================================
# eu-west — AWS eu-west-1
# =============================================================================

cert "lh_euw_1" {
  networks    = ["10.20.0.1/16"]
  groups      = ["lighthouse", "eu_west"]
  output_dir = "out/sites/eu-west"
}

cert "app_euw_1" {
  networks    = ["10.20.1.1/16"]
  groups      = ["app", "eu_west"]
  output_dir = "out/sites/eu-west"
}

cert "app_euw_2" {
  networks    = ["10.20.1.2/16"]
  groups      = ["app", "eu_west"]
  output_dir = "out/sites/eu-west"
}

cert "app_euw_3" {
  networks    = ["10.20.1.3/16"]
  groups      = ["app", "eu_west"]
  output_dir = "out/sites/eu-west"
}

cert "ci_euw_1" {
  networks    = ["10.20.2.1/16"]
  groups      = ["ci", "eu_west"]
  output_dir = "out/sites/eu-west"
}

cert "ci_euw_2" {
  networks    = ["10.20.2.2/16"]
  groups      = ["ci", "eu_west"]
  output_dir = "out/sites/eu-west"
}

# =============================================================================
# us-east — AWS us-east-1
# =============================================================================

cert "lh_use_1" {
  networks    = ["10.30.0.1/16"]
  groups      = ["lighthouse", "us_east"]
  output_dir = "out/sites/us-east"
}

cert "app_use_1" {
  networks    = ["10.30.1.1/16"]
  groups      = ["app", "us_east"]
  output_dir = "out/sites/us-east"
}

cert "app_use_2" {
  networks    = ["10.30.1.2/16"]
  groups      = ["app", "us_east"]
  output_dir = "out/sites/us-east"
}
