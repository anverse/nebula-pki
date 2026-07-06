# Revocation strategy

## Status

accepted (revocation deferred)

## Context

Nebula has no PKI revocation list protocol. Recent versions (1.9+) support a `pki.blocklist` field in each node's `config.yaml` that lists fingerprints to reject. The blocklist is a **runtime** concern: it lives in the Nebula daemon's config file, not in any certificate the CA issues.

This tool wraps `nebula-cert`. `nebula-cert` itself does not manage a blocklist — it only issues and inspects certificates.

## Decision

Blocklist management is **out of scope** for this tool. There is no `blocklist_entry` block in the HCL schema and no blocklist field in the manifest.

Revocation, when needed, is handled by the downstream tooling that renders each host's `config.yaml`. That tooling is free to:

- Maintain its own list of revoked fingerprints.
- Read the manifest's `hosts` map to discover current fingerprints.
- Compare a separate, project-specific "decommissioned" list against the manifest to compute blocklist entries.

The tool's only revocation-adjacent feature is that the manifest records every issued fingerprint, making it trivial for downstream tooling to identify which fingerprint belongs to which host.

## Consequences

- The CLI stays tightly aligned with `nebula-cert`'s feature surface.
- No false impression that issuing a "revoke" command via this tool affects any running Nebula network.
- Removing a host from the HCL deletes its manifest entry on the next run. Whether its certificate files on disk are also deleted is a tool decision (see ADR-002: artifacts of removed hosts are removed from the manifest; on-disk files are left untouched and may be cleaned up manually).
- Operators who want declarative revocation can layer it on top of this tool by maintaining a small companion file consumed by their config-rendering pipeline.
- If a future need emerges for first-class blocklist management here, it can be added as an additive feature without breaking the current schema.
