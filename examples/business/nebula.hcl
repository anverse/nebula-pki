# Business example — multi-site corporate mesh on 10.0.0.0/8.
#
# One CA, three sites, each with its own output_dir so the relevant
# deploy target (Terraform / Ansible) reads from its own directory.
#
# This example is meant to show "yes, this scales beyond a homelab",
# but the tool is still aimed at the dozens-of-hosts range, not
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

  # Restrict the group vocabulary. Hosts may only use groups from this
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

storage {
  out_dir = "out"
}

# -----------------------------------------------------------------------------
# Output directories — one per site.
#
# Each host names its destination via `output_dir`. The per-site deploy
# pipeline (Terraform module, Ansible inventory, ...) reads from these
# directories. Filenames are always <host.name>.crt and
# <host.name>.key.enc, derived from the host label.
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
host "lh_hq_1" {
  networks    = ["10.10.0.1/16"]
  groups      = ["lighthouse", "hq"]
  output_dir  = "out/sites/hq"
}

host "lh_hq_2" {
  networks    = ["10.10.0.2/16"]
  groups      = ["lighthouse", "hq"]
  output_dir  = "out/sites/hq"
}

# Admin workstations (operators). Default placement, no `output_dir`,
# since admin keys don't ship with the site deploy.
host "admin_1" {
  networks = ["10.10.0.10/16"]
  groups   = ["admin", "hq"]
}

host "admin_2" {
  networks = ["10.10.0.11/16"]
  groups   = ["admin", "hq"]
}

# App servers.
host "app_hq_1" {
  networks    = ["10.10.1.1/16"]
  groups      = ["app", "hq"]
  output_dir  = "out/sites/hq"
}

host "app_hq_2" {
  networks    = ["10.10.1.2/16"]
  groups      = ["app", "hq"]
  output_dir  = "out/sites/hq"
}

host "app_hq_3" {
  networks    = ["10.10.1.3/16"]
  groups      = ["app", "hq"]
  output_dir  = "out/sites/hq"
}

# Database (primary + replica).
host "db_hq_primary" {
  networks    = ["10.10.2.1/16"]
  groups      = ["db", "hq"]
  output_dir  = "out/sites/hq"
}

host "db_hq_replica" {
  networks    = ["10.10.2.2/16"]
  groups      = ["db", "hq"]
  output_dir  = "out/sites/hq"
}

# Edge router. Bridges the overlay onto the HQ office LAN so admins on
# the office Wi-Fi can reach overlay services without each laptop
# joining the mesh directly. `unsafe_networks` advertises the route;
# Nebula's firewall on each peer decides whether to honour traffic to
# 192.168.10.0/24.
host "router_hq" {
  networks        = ["10.10.9.1/16"]
  unsafe_networks = ["192.168.10.0/24"]
  groups          = ["router", "hq"]
  output_dir      = "out/sites/hq"
}

# =============================================================================
# eu-west — AWS eu-west-1
# =============================================================================

host "lh_euw_1" {
  networks    = ["10.20.0.1/16"]
  groups      = ["lighthouse", "eu_west"]
  output_dir = "out/sites/eu-west"
}

host "app_euw_1" {
  networks    = ["10.20.1.1/16"]
  groups      = ["app", "eu_west"]
  output_dir = "out/sites/eu-west"
}

host "app_euw_2" {
  networks    = ["10.20.1.2/16"]
  groups      = ["app", "eu_west"]
  output_dir = "out/sites/eu-west"
}

host "app_euw_3" {
  networks    = ["10.20.1.3/16"]
  groups      = ["app", "eu_west"]
  output_dir = "out/sites/eu-west"
}

host "ci_euw_1" {
  networks    = ["10.20.2.1/16"]
  groups      = ["ci", "eu_west"]
  output_dir = "out/sites/eu-west"
}

host "ci_euw_2" {
  networks    = ["10.20.2.2/16"]
  groups      = ["ci", "eu_west"]
  output_dir = "out/sites/eu-west"
}

# =============================================================================
# us-east — AWS us-east-1
# =============================================================================

host "lh_use_1" {
  networks    = ["10.30.0.1/16"]
  groups      = ["lighthouse", "us_east"]
  output_dir = "out/sites/us-east"
}

host "app_use_1" {
  networks    = ["10.30.1.1/16"]
  groups      = ["app", "us_east"]
  output_dir = "out/sites/us-east"
}

host "app_use_2" {
  networks    = ["10.30.1.2/16"]
  groups      = ["app", "us_east"]
  output_dir = "out/sites/us-east"
}
