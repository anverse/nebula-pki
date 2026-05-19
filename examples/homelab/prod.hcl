# Homelab — prod environment.
#
# Same overlay /16 as dev (172.16.0.0/16), different host ranges, and a
# distinct CA. The two CAs are signed independently, so a prod host
# cannot authenticate to dev and vice versa.
#
# Address plan:
#   172.16.0.0/16     — overlay
#   172.16.100.0/24   — admin laptops, phones
#   172.16.110.0/24   — cluster control-plane nodes
#   172.16.120.0/24   — cluster worker nodes (uncomment below when needed)
#
# See ./example.md for the walkthrough.

ca {
  name     = "homelab-prod"
  duration = "26280h"     # ~3 years
  networks = ["172.16.0.0/16"]
}

storage {
  out_dir       = "out/prod"
  manifest_file = "out/prod/nebula-pki.json"

  encryption "sops" {}
}

# Control-plane nodes. Three live nodes plus spares for replacement.
host "node_1" { networks = ["172.16.110.1/16"] groups = ["cluster", "control_plane", "lighthouse"] output_dirs = ["out/prod/cluster"] }
host "node_2" { networks = ["172.16.110.2/16"] groups = ["cluster", "control_plane", "lighthouse"] output_dirs = ["out/prod/cluster"] }
host "node_3" { networks = ["172.16.110.3/16"] groups = ["cluster", "control_plane", "lighthouse"] output_dirs = ["out/prod/cluster"] }
host "node_4" { networks = ["172.16.110.4/16"] groups = ["cluster", "control_plane", "lighthouse"] output_dirs = ["out/prod/cluster"] }
host "node_5" { networks = ["172.16.110.5/16"] groups = ["cluster", "control_plane", "lighthouse"] output_dirs = ["out/prod/cluster"] }

# Worker nodes (optional). Uncomment as the cluster grows.
# host "worker_1" {
#   networks    = ["172.16.120.1/16"]
#   groups      = ["cluster", "worker"]
#   output_dirs = ["out/prod/cluster"]
# }

# Admin laptops.
host "laptop_1" {
  networks = ["172.16.100.1/16"]
  groups   = ["admin", "remote"]
}

host "laptop_2" {
  networks = ["172.16.100.2/16"]
  groups   = ["admin", "remote"]
}

# Mobile devices — see dev.hcl for the workflow. Commented until needed.
#
# host "phone_1" {
#   networks = ["172.16.100.10/16"]
#   groups   = ["admin", "mobile"]
#   in_pub   = "./mobile-pubkeys/phone_1.pub"
# }
