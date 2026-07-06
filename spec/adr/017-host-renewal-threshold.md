# Host renewal threshold (`renew_before`)

## Status

accepted

## Context

[ADR-002](./002-state-and-artifact-layout.md) defined the idempotency rule for host certificates: a host is re-signed when its cert content changes, its `duration` literal changes, the active CA changes, or its artifacts go missing. It explicitly deferred *time-based* renewal:

> Renewal-before-expiry is not automatic in v1. Operators bump `duration` (or run with `--force`, deferred) when they want a new `not_after`. A future ADR may add a renewal threshold.

This is that ADR.

The deferred behaviour is a real operational gap. Host certificates default to expiring one second before their signing CA, but operators frequently set shorter per-host durations (a laptop on `720h`, say). With no renewal threshold, the tool considers such a host "up to date" right up until the instant it expires, then the host drops off the Nebula network. The only remedies under the ADR-002 rules are awkward:

- **Bump `duration`** — but that changes the validity *length*, not just the expiry, and an operator who wants a steady 30-day cert does not want to keep editing the number.
- **`--force`** — re-signs *everything*, indiscriminately, and is itself deferred.

Time-based renewal is also what makes **CA rotation** ([ADR-016](./016-ca-rotation-and-trust-bundles.md)) ergonomic. After moving the `default = true` marker to the new CA, an operator wants hosts to migrate onto it on their normal cadence rather than via a manual sweep. A renewal threshold turns a scheduled `nebula-pki` run into the thing that gradually re-signs hosts as they approach expiry.

## Decision

Add an optional `renew_before` duration, settable per host and as a CA-level default. A certificate is considered stale — and re-signed on the next run — when it is within `renew_before` of its `not_after`.

```hcl
ca "current" {
  name         = "mesh-2026"
  renew_before = "720h"        # default for hosts signed by this CA
}

host "laptop" {
  networks     = ["10.42.5.5/16"]
  duration     = "2160h"        # 90-day cert
  renew_before = "720h"         # re-sign once inside the last 30 days
}
```

### Semantics

- `renew_before` is a duration. The host is stale when `now + renew_before >= not_after`.
- **Resolution order** for a host's effective threshold:
  1. `host.renew_before` if set;
  2. else the signing CA's `ca.renew_before` if set;
  3. else **unset** — no time-based renewal, exactly the ADR-002 behaviour (re-sign only on content/duration/CA/artifact change). This keeps the default behaviour unchanged for anyone who does not opt in.
- It extends, and does not replace, the ADR-002 idempotency rule. A host is up to date when **all** ADR-002 conditions hold **and** it is not within `renew_before` of expiry. Any single failing condition triggers a re-sign.
- `renew_before` must be **less than** the host's effective validity (`duration`, or CA-expiry-minus-1s when `duration` is unset). A threshold greater than or equal to the validity would make the cert stale the moment it is issued, causing a re-sign on every run — an infinite-churn foot-gun. This is a validation error.
- The manifest records the resolved `renew_before` literal alongside `duration`, so the staleness verdict is reproducible across runs and machines.

### Interaction with idempotency and `not_after` drift

ADR-002 records the **literal** `duration` (not the resolved `not_after`) precisely so that re-runs are idempotent. `renew_before` is evaluated against the recorded `not_after` of the *last* signing. The consequence is intended:

- Outside the window: re-runs write nothing; the tree stays byte-identical.
- Inside the window: the host is re-signed once, `not_after` jumps forward by `duration`, and the host immediately falls *outside* the window again. The next run is a no-op. So a single run inside the window renews exactly once — no churn, no loop.

Because renewal depends on wall-clock time, two runs straddling the threshold legitimately differ (one no-op, one renewal). This is the one place the tool is intentionally not time-invariant, and it is the whole point of the feature. The injectable `pki.Clock` already used in tests (see the v0.1 milestone) makes this deterministically testable.

### Not a daemon, not a cron

`nebula-pki` does not run in the background. `renew_before` only does anything when the tool is actually invoked. The intended deployment is the same scheduled CI/GitOps run that already reconciles the Nebula network (e.g. a nightly pipeline): on each run, any host inside its window is re-signed and the new artifacts are committed/distributed by the existing pipeline. The tool provides the *threshold*; the operator's scheduler provides the *cadence*. This keeps the tool a single-shot reconciler (no new long-running mode, consistent with [ADR-001](./001-tooling-approach.md)).

### Reporting the next deadline

Because the tool is single-shot, the operator's recurring question is *"when do I need to run this again?"* After every reconcile (and every `--dry-run`), `nebula-pki` answers it by printing, to **stderr**, the single earliest actionable deadline computed from the post-run manifest, plus a short summary of what is expiring soon.

The earliest actionable deadline is the soonest of:

- the next moment a host **enters its `renew_before` window** (`not_after − renew_before`), for hosts that have a threshold — this is the date by which a run would actually renew the cert; and
- the next **expiry** (`not_after`) of any certificate that has **no** `renew_before` — a CA, or a host without a threshold — because nothing will auto-renew it and it will simply lapse.

Reporting both in one number is deliberate: a host with a threshold wants you to run *before its window closes* (so renewal happens with margin), while an item without a threshold wants you to run *before it expires*. The smaller of the two is the honest "run again before this" answer.

Output shape (illustrative; exact wording settled during implementation):

```
reconciled: CA up to date, 12 hosts up to date
next renewal due: host "laptop" enters its renewal window on 2027-04-18 (in 27d)
  also expiring soon: CA "current" not-after 2027-05-17 (in 56d); host "edge" not-after 2027-04-30 (in 39d)
hint: run nebula-pki again before 2027-04-18 to keep the Nebula network current
```

Rules:

- **When.** Printed on reconcile and `--dry-run`, including **no-op** runs — the whole point is that an operator can re-run at any time purely to re-read "when next." Not printed by `check` (it does not read `out/`) or `version`.
- **Stream.** stderr, like other progress/advisory output; it is advisory, not machine-consumed. Downstream tooling that wants these dates reads them from the manifest (`not_after`, `renew_before`), not by scraping stdout.
- **Soon threshold.** The "also expiring soon" line lists items whose deadline falls within a small, fixed look-ahead window (e.g. the next 60 days; final value chosen in implementation). When nothing is within the window, only the single "next renewal due" line is printed.
- **Nothing due / empty Nebula network.** With no hosts and only a long-lived CA, the line still reports the CA's expiry. With no certificates at all, the deadline section is omitted.
- **Past-due / expired.** Any certificate already inside its window (or already expired) that was *not* re-signed this run — e.g. an `in_pub` host whose upstream public key is missing, or a reference-mode CA the operator owns — is surfaced as **overdue** in the same block, so a stale deadline is never silently hidden.
- **Determinism.** "now" comes from the injectable `pki.Clock`, so the printed relative offsets (`in 27d`) are deterministic under test.

This is purely informational. It changes no exit code and triggers no writes; it reads the same `not_after` / `renew_before` data the idempotency verdict already uses.

## Consequences

### Positive

- Short-lived host certs become practical: set `duration` and `renew_before` once, schedule the tool, and certs renew themselves before expiry.
- CA rotation self-heals: after the `default = true` marker moves to the new CA, hosts migrate onto it as they enter their renewal window, instead of via a manual `--force` sweep.
- The operator never has to guess when to run again: every run ends with the earliest actionable deadline, so even an ad-hoc (non-scheduled) workflow gets a "run again before <date>" prompt. Re-running anytime re-answers it from current state.
- The default is unchanged. Configs without `renew_before` behave exactly as ADR-002 specifies. No churn is introduced for anyone who does not opt in.
- `--force` (still deferred) is no longer the *only* answer to renewal, narrowing what `--force` must eventually do.

### Negative

- Re-runs are no longer guaranteed byte-identical for hosts that have `renew_before` set and have crossed the threshold — by design. The "unchanged config → unchanged tree" property in ADR-002 now carries the qualifier "given a fixed clock and no host inside its renewal window." The e2e idempotency scenarios must pin the clock (already planned) to stay deterministic.
- Operators can misconfigure `renew_before` close to `duration` and get frequent re-signs (though never an infinite loop, since each re-sign pushes `not_after` forward). The "must be less than validity" validation catches the pathological case; the merely-aggressive case is the operator's call.
- Renewal re-signs produce new key material by default (a fresh keypair per sign, as in `nebula-cert`). Hosts using `in_pub` ([ADR-018](./018-in-pub-air-gapped-signing.md)) are the exception — there is no key to rotate, only the cert — and a host whose key must remain stable across renewals should use that flow.
- The printed deadline reflects the manifest *as of this run*. It is an aid, not a guarantee: if the operator changes `duration`/`renew_before` later, or never runs again, the date is moot. It deliberately does not arrange to fire on that date (no daemon/cron — that is the scheduler's job).

## Considered alternatives

### A. No threshold; rely on `duration` edits and `--force`

The ADR-002 status quo. Rejected: it makes short-lived certs impractical and forces a manual sweep for both ordinary renewal and CA rotation. The whole value of a reconciler is lost at the most important moment — keeping the Nebula network from going dark.

### B. Renew at a fixed fraction of validity (e.g. always at 2/3 of lifetime)

Rejected: less explicit than a duration and surprising when `duration` varies across hosts. An absolute `renew_before` duration is what operators reason about ("renew 30 days out"), and it composes cleanly with a CA-level default.

### C. A separate `nebula-pki renew` subcommand

Rejected: renewal is not a distinct intent, it is part of reconciliation. Folding it into the staleness verdict keeps one command and one mental model; a separate verb would re-implement the same comparison with a different name.

## Links

- [ADR-002](./002-state-and-artifact-layout.md) — the idempotency rule this extends; records the `renew_before` literal in the manifest.
- [ADR-016](./016-ca-rotation-and-trust-bundles.md) — CA rotation, the workflow `renew_before` makes self-healing.
- [ADR-001](./001-tooling-approach.md) — single-shot CLI, no long-running mode; `renew_before` needs a scheduler, not a daemon.
- [ADR-008](./008-cli-surface.md) — CLI surface; the post-run "next deadline" line is advisory stderr output, distinct from the deferred `show` subcommand (which would pretty-print the full manifest on demand).
- [ADR-018](./018-in-pub-air-gapped-signing.md) — `in_pub` hosts renew the cert without rotating a key.
