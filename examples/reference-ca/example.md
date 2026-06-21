# Reference-CA example

Use an existing CA instead of letting `nebula-pki` mint one. This is the
right shape when the certificate authority is owned outside this tool — a
shared root another team controls, a CA you created once with
`nebula-cert ca` and keep under separate access control, or a CA you
rotate by hand.

For a from-scratch CA the tool generates and owns, see
[`../homelab/`](../homelab/example.md) or
[`../business/`](../business/example.md).

## Files

| File | Purpose |
|---|---|
| [`nebula.hcl`](./nebula.hcl) | Reference-mode CA block plus (commented) host blocks. |

## How reference mode behaves

The CA block names two existing files and nothing else:

```hcl
ca "shared-root" {
  cert_file = "ca.crt"
  key_file  = "ca.key"
}
```

On `nebula-pki check` and on a reconcile run, the tool:

- reads `cert_file` and `key_file` **in place** and never rewrites them;
- verifies the pair — the certificate must be a CA, its self-signature
  must verify, the key's curve must match the certificate, and the key
  must correspond to the certificate's public key;
- records `ca.mode = "reference"` in `out/nebula-pki.json` with the CA's
  fingerprint, validity window, and the referenced paths;
- writes **nothing** under `out/ca/` — that directory is only for CAs the
  tool generates.

A missing `cert_file`/`key_file` is a hard error. An expired referenced CA
is recorded anyway, with a warning on stderr: in reference mode the CA is
yours to manage, and refusing would block you from inspecting or rotating
it.

Generate-only fields (`name`, `duration`, `curve`, `version`, `encrypt`,
`argon_*`, `out_*`) are rejected — they describe how a CA would be
*created*, and reference mode creates nothing.

## Running

```sh
# Produce a CA to reference (or use one you already have).
nebula-cert ca -name "shared-root" -out-crt ca.crt -out-key ca.key

# Validate the config and confirm which CA you are pointed at.
nebula-pki check
# config valid: nebula.hcl (ca mode=reference, hosts=0)
#   ca verified: name="shared-root" fingerprint=<hex>

# Record the referenced CA in the manifest.
nebula-pki
# using referenced CA "shared-root"
#   cert: ca.crt
#   key:  ca.key
# wrote manifest: out/nebula-pki.json
```

Resulting layout:

```
reference-ca/
  nebula.hcl
  ca.crt                  # yours; untouched by nebula-pki
  ca.key                  # yours; untouched by nebula-pki
  out/
    nebula-pki.json       # mode=reference, records the CA fingerprint
```

A second run against the same referenced CA writes nothing and leaves the
manifest byte-identical. Point `cert_file`/`key_file` at a different CA and
the next run updates the recorded fingerprint.

The manifest is safe to commit: it holds the CA fingerprint, validity, and
paths — no key material.

## Hosts

Hosts are signed under the referenced CA exactly as they would be under a
generated one; the `host` blocks in `nebula.hcl` are commented out because
host signing lands in a later `0.0.x` release. Nothing about the host
blocks changes between generate and reference mode — only the CA block
differs.
