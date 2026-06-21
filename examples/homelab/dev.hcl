# Homelab — dev environment.
#
# A typical small homelab mesh: a handful of cluster nodes (k3s in this
# example, but the tool doesn't care), a couple of admin laptops, and an
# optional phone or two. Dev and prod share the same overlay /16 but use
# different host ranges and different CAs, so a dev host cannot
# authenticate to prod and vice versa.
#
# Address plan (mirrors the prod.hcl layout):
#   172.16.0.0/16   — overlay
#   172.16.0.0/24   — admin laptops, phones
#   172.16.1.0/24   — cluster control-plane nodes
#   172.16.2.0/24   — cluster worker nodes (uncomment below when needed)
#
# See ./example.md for the walkthrough, including the mobile workflow.

ca "homelab-dev" {
  name     = "homelab-dev"
  duration = "26280h"     # ~3 years
  networks = ["172.16.0.0/16"]
}

storage {
  out_dir       = "out/dev"
  manifest_file = "out/dev/nebula-pki.json"
}

# Cluster certs go into a dedicated directory so the downstream consumer
# (Ansible, Terraform, ...) can read just the cluster material. Each host
# points at the directory via `output_dir`.

# -----------------------------------------------------------------------------
# Control-plane nodes.
#
# Three are signed up-front. The `lighthouse` group is carried by every
# control-plane cert, but only one node actually runs as a Nebula
# lighthouse in dev. Lighthouse selection is a runtime decision in
# config.yaml, not a cert property.
# -----------------------------------------------------------------------------

host "node_1" {
  networks    = ["172.16.1.1/16"]
  groups      = ["cluster", "control_plane", "lighthouse"]
  output_dir  = "out/dev/cluster"
}

host "node_2" {
  networks    = ["172.16.1.2/16"]
  groups      = ["cluster", "control_plane", "lighthouse"]
  output_dir  = "out/dev/cluster"
}

host "node_3" {
  networks    = ["172.16.1.3/16"]
  groups      = ["cluster", "control_plane", "lighthouse"]
  output_dir  = "out/dev/cluster"
}

# Pre-signed spares for node replacement. Comment out anything you don't
# expect to provision in the foreseeable future.

host "node_4" {
  networks    = ["172.16.1.4/16"]
  groups      = ["cluster", "control_plane", "lighthouse"]
  output_dir  = "out/dev/cluster"
}

host "node_5" {
  networks    = ["172.16.1.5/16"]
  groups      = ["cluster", "control_plane", "lighthouse"]
  output_dir  = "out/dev/cluster"
}

# -----------------------------------------------------------------------------
# Worker nodes (optional). Uncomment as the cluster grows.
# -----------------------------------------------------------------------------

# host "worker_1" {
#   networks    = ["172.16.2.1/16"]
#   groups      = ["cluster", "worker"]
#   output_dir  = "out/dev/cluster"
# }

# -----------------------------------------------------------------------------
# Admin laptops.
#
# Default placement: out/dev/hosts/<name>.crt — no `output_dir`,
# since admin keys typically don't ship alongside the cluster deploy.
# -----------------------------------------------------------------------------

host "laptop_1" {
  networks = ["172.16.0.1/16"]
  groups   = ["admin", "remote"]
}

host "laptop_2" {
  networks = ["172.16.0.2/16"]
  groups   = ["admin", "remote"]
}

# -----------------------------------------------------------------------------
# Mobile devices.
#
# The Nebula iOS/Android app generates its keypair on-device. The private
# key never leaves the phone. We only sign the public key the app exports.
# That maps to `nebula-cert sign -in-pub <file>`, exposed here as `in_pub`.
#
# Workflow:
#   1. In the Nebula app: "Sites" -> "+" -> "Create a Site Manually" ->
#      "Generate Key Pair". Export/share the public key (one text block).
#   2. Save it to ./mobile-pubkeys/<host_label>.pub in this directory.
#   3. Uncomment / add the host block below and re-run nebula-pki.
#   4. Send the resulting .crt and the CA cert back to the phone.
#      No .key file is produced for these hosts — the phone already has it.
# -----------------------------------------------------------------------------

# host "phone_1" {
#   networks = ["172.16.0.10/16"]
#   groups   = ["admin", "mobile"]
#   in_pub   = "./mobile-pubkeys/phone_1.pub"
# }
