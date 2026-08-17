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

## Amendment, 2026-08-17

The first implementation emitted the panel's *rows* but not the panel's *cuts*,
and dropped one key it had promised to keep. A third black-box pass against the
published 2.15.0 package reported both. Neither changes the decision above; they
complete it.

- **The lists are cut the way the panel cuts them.** Default `--plain` carries
  the panel's high-signal related-domain selection and its insight cap, each
  with a sibling `related_domains_note:` / `insights_note:` key stating how many
  entries were withheld and which flag restores them. The unreduced lists stay
  behind `--plain --full`. Without this the flag was a briefing on a sparse name
  and a 144-line hostname roll call on a populated one, which is the reported
  accessibility cost in its original form.
- **`provider:` is emitted on role-split records too**, after `mail:` and
  `identity:` rather than before them. Dropping it made the documented
  `grep provider:` miss silently on exactly the record class ADR-0015 exists
  for. It carries the same MX-delivery-path summary it carries everywhere else,
  and placing it after the role keys keeps a top-down reader meeting the roles
  first, which was the reason for dropping it from the visual panel.

`--plain` also now honors `--confidence-mode`, because a flag that changes the
panel's insight wording has to change the panel's linear form as well.

## Second amendment, 2026-08-17: a note counts against the flag it names

The fourth pass read the note keys as a scripting contract and found the
arithmetic did not close. The cause was a basis mismatch: the notes were
computed from the panel's curated list, then printed on the surface that emits
the record. Three surfaces exist, not two, and they nest: the record, the
panel's curation of it, and the default cap.

- **The insight remainder was the cap alone.** The panel also drops restatement
  lines (`Provider indicators co-observed:`, `MX gateway observed:`) that the
  record keeps, so `--plain --full` printed more than the note accounted for.
- **A record under the cap said nothing at all.** Curated list of three,
  record of five, no note: silence reads as "you have everything", which is the
  failure the notes exist to prevent, and it fires on any record carrying a
  dual-provider or gateway restatement, which is the record class ADR-0015 is
  about.
- **The related total skipped what `--full` prints.** Wildcards and
  `*.onmicrosoft.*` names are left out of the selection, and were left out of
  the total as well, on both renderers.

The rule is now that a note's remainder counts against the output its own text
names, and that the text names the command the reader has to type. On `--plain`
that is `--plain --full`, the whole record. The panel's footer counts against
the panel's `--full`, which stays curated because collapsing four wordings of
one fact into one line is a claim-inflation guard, not a space saving, and
`--full` is no place to undo it. So the two remainders can differ for one
record. Naming the destination is what keeps that from reading as a
contradiction: two numbers answering one question is a defect, two numbers
answering two named questions is not. The related-domain total is the list
length on both, which converges them.

`provider:` on a role split also now keeps its evidence role, `provider: Google
Workspace (MX delivery path)`. ADR-0012 compacts roles out of the default view;
this key is the exception because on a split it is the only line that repeats a
vendor word the reader has already heard, and the role is what makes the second
hearing a different fact rather than a stutter. The play-test recommended
keeping the key and tagging the value, over dropping either.

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
