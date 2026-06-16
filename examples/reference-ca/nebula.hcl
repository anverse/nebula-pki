# Reference mode — sign against a CA you already have.
#
# Instead of minting a CA, point nebula-pki at an existing ca.crt / ca.key
# pair. This is the right shape when the CA is owned elsewhere — a shared
# root managed by another team, a CA generated once by `nebula-cert ca`
# and kept under separate control, or a CA you rotate by hand.
#
# nebula-pki reads the two files in place and never rewrites them. On a
# run it verifies the pair (the cert must be a CA, its self-signature must
# verify, and the key must match the cert), records the CA's fingerprint
# and validity window in the manifest under `ca.mode = "reference"`, and
# leaves out/ca/ empty. An expired referenced CA is recorded anyway, with
# a warning — in reference mode the CA is yours to manage.
#
# Reference mode rejects every generate-only field (duration, curve,
# version, encrypt, argon_*, out_*): those describe how a CA would be
# *created*, and here nothing is created. Both cert_file and key_file are
# required.
#
# Try it:
#   # produce a throwaway CA to reference
#   nebula-cert ca -name "shared-root" -out-crt ca.crt -out-key ca.key
#   nebula-pki check           # reads ca.crt/ca.key, prints the fingerprint
#   nebula-pki                 # records it in out/nebula-pki.json
#
# See ./example.md for the walkthrough.

ca {
  cert_file = "ca.crt"
  key_file  = "ca.key"
}

storage {
  out_dir = "out"
}

# Hosts are signed under the referenced CA exactly as they would be under a
# generated one. (Host signing lands in a later 0.0.x release; the blocks
# below are how they will read.)
#
# host "gateway" {
#   networks = ["10.50.0.1/16"]
#   groups   = ["edge"]
# }
#
# host "worker_1" {
#   networks    = ["10.50.10.1/16"]
#   groups      = ["worker"]
#   output_dirs = ["out/site-a"]
# }
