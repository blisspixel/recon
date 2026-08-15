# ADR-0016: `--plain` emits the panel, `--plain --full` emits the record

- **Status:** Accepted
- **Date:** 2026-08-15

## Context

`--plain` is recon's accessibility and scripting surface. It has always
linearized the **entire** structured record: the same dictionary `--json`
serializes, rendered as indented `key: value` lines. On an ordinary apex that is
around 350 lines, opening with schema keys and including
`posterior_observations`, `interval_low`, `cert_summary.deployment_bursts`, and
every retained evidence record.

Two consecutive black-box play-tests reported the same thing: the accessibility
path is the hardest path. A screen-reader user following the documented
recommendation hears Bayesian interval bounds before they hear which vendor
handles mail. The 2.14.1 pass measured 358 lines and, after the description was
corrected to say "full record", still argued the description was not the fix:

> A screen-reader user who wants the compact panel still cannot have it without
> parsing Rich boxes or 350 lines of schema keys. Grep users are served.

recon corrected the *wording* in 2.14.1: the banner, `docs/getting-started.md`,
and the flag help now all say "full record" rather than promising a panel. That
closed the truthfulness defect and left the capability gap: there is no linear
rendering of the compact panel, so the only way to get recon's actual summary is
to read a box-drawn panel or to reimplement the summary from JSON.

The full-record dump is genuinely useful and has consumers, so removing it is
not an option. The question is only which behavior `--plain` with no further
flags should have.

## Decision

`--plain` renders the **default panel's rows**, linearly. `--plain --full`
renders the complete structured record exactly as `--plain` does today.

- Default `--plain` emits the same claims the visual panel shows, in panel
  order, as `key: value` lines with no color and no box drawing: the domain, the
  vendor rows (including the role-split rows from
  [ADR-0015](0015-role-split-vendor-claims-in-the-default-view.md) when they
  apply), tenant, auth, confidence, the service categories, and insights.
- `--plain --full` emits the current full-record linearization, unchanged. The
  existing `--full` flag already means "more detail" everywhere else in the CLI,
  so this composes with the surface a caller already knows.
- `--plain --explain` and `--plain --verbose` keep tracking the panel's
  detailed view, including evidence-role qualifiers, as ADR-0012 requires.
- The key names in default `--plain` remain the stable schema names
  (`tenant_id`, `auth_type`), so a `grep tenant_id:` written against today's
  output still matches tomorrow's.

## Consequences

This is a **breaking change to the `--plain` output contract**, which
`docs/stability.md` governs. A pipeline that parses default `--plain` for a
field outside the panel (a posterior bound, a certificate burst) gets fewer
keys and must add `--full`. That is a real migration cost, accepted for three
reasons: the accessibility surface is the one recon documents for users who have
the fewest alternatives; the exact prior bytes remain available behind one
documented flag; and `--json` has always been the surface recon tells automation
to use, and it is untouched.

`--json`, `--csv`, `--md`, the MCP payloads, the cache, and the capsule schema
are unchanged. This ADR governs one human-facing renderer.

The change ships with the release that carries it called out in
`CHANGELOG.md` under `Tool Surface Changes`, and `docs/stability.md` records
`--plain` default output as changed with the `--full` migration path named.

## Alternatives considered

**Keep the dump and drop "screen readers" from the help.** Honest, zero code
change, and it was recon's 2.14.1 position. Rejected because it resolves the
contradiction by withdrawing the promise rather than by shipping the capability,
leaving screen-reader users with no compact mode at all. The play-test
explicitly argued against it.

**Add a separate `--brief` flag and leave `--plain` alone.** Zero risk to
existing consumers. Rejected because it grows the flag surface the roadmap is
actively trying to cut, and because it leaves the documented accessibility flag
pointing at the least accessible output, a discoverability trap for exactly the
users least able to afford one.
