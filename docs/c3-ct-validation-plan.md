# Closed Certificate-Transparency Validation Plan

Status: closed on 2026-06-26 after Session F, the Infobip promotion, local gate,
and remote readiness. This document records the executed maintainer plan for the
certificate-transparency corpus track without changing recon's runtime surface.

The plan is intentionally bounded. CT is a public monitoring system and a useful
source of certificate and subdomain evidence, but it is not a free bulk data
warehouse. The track proved recon's certificate-transparency paths, graph
surfaces, retry accounting, and catalog-triage discipline under real provider
constraints. It did not try to force complete CT coverage through public search
endpoints.

## Research Basis

Reviewed on 2026-06-26:

- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html): CT logs are public
  services for logging TLS certificates so anyone can audit CA activity and
  monitor for unexpected issuance. This supports using CT as passive evidence,
  but the standard is about logs and monitors, not bulk domain enumeration.
- [Let's Encrypt CT log documentation](https://letsencrypt.org/docs/ct-logs/):
  the page was last updated 2026-06-15 and documents active production static
  CT logs. That confirms the ecosystem is moving toward monitor-friendly static
  read paths while older RFC 6962 API logs are retiring in some deployments.
- [C2SP Static CT API](https://c2sp.org/static-ct-api): Static CT defines a
  read-path hierarchy for monitors alongside write-path CT APIs. It is a log
  monitoring interface, not a domain-indexed search API.
- [SSLMate Certificate Search API](https://sslmate.com/ct_search_api/) and
  [pricing](https://sslmate.com/pricing/ct_search_api): domain-indexed CT
  search is a convenience layer over many logs, with explicit hourly and
  per-minute limits even on the free tier. Bulk corpus use must respect that.
- [NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final): aggregate
  release is a governed disclosure process, not a string-redaction trick.
  Certificate-transparency memos must remain counts-only, suppress small cells,
  and avoid rows.
- [Diataxis](https://diataxis.fr/): keep orientation, task guidance, reference,
  and explanation separated. That is why this plan lives outside the README and
  why the roadmap points here instead of carrying command-level details.
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
  [Semantic Versioning](https://semver.org/): certificate-transparency updates
  belong under `Unreleased`; patch-line work must avoid new stable runtime
  surfaces.
- [Infobip domain setup documentation](https://www.infobip.com/docs/email/get-started-with-email/set-up-your-domain):
  vendor-published email DNS setup names the `email-messaging.com` tracking
  and sending host family. That supports extending the existing `infobip`
  surface rule narrowly instead of creating a second provider identity.

## Current State

The certificate-transparency validation track has seven private sessions
documented in
[../validation/2026-06-26-c3-ct-partial.md](../validation/2026-06-26-c3-ct-partial.md).

Aggregate state:

- Sessions summarized: 7.
- Valid records across sessions: 2,947.
- Records with a domain field: 2,909.
- Unique domains observed across sessions: 2,647.
- Domains with CT data: 44.
- CT-data coverage ratio: 0.016623.
- Domains still degraded or unresolved for CT: 2,603.
- External spend: 0 USD.

What changed in the latest cycle:

- Retry Session D completed the 32 degraded records from Retry Session C, added
  one live CT success, and produced no candidates.
- Retry Session E completed the next 31-record retry corpus, added one live CT
  success, and produced one candidate: an Infobip regional email-tracking CNAME
  target under `email-messaging.com`.
- The candidate was promoted only after public-source review against Infobip's
  email domain setup documentation. The existing `infobip` slug now has a
  second narrow `cname_target` rule for `email-messaging.com`, a lookalike
  negative test, and an explicit Email panel-category mapping.
- Retry Session F ran as the final bounded post-promotion check against the
  degraded tail from Session E. It finalized 15 records before the runtime cap,
  added two live CT successes, and produced zero candidates.
- Provider health remains the limiting factor: crt.sh is breaker-gated or
  intermittently returning HTTP 503, while CertSpotter can recover only a small
  number of free unauthenticated results between local cooldown windows.

## Why This Was Next

This was the top roadmap item because it was the only open validation task that
exercised all of these surfaces together:

- CT provider failure modes and cache fallback.
- CT attempt-outcome accounting.
- Certificate and graph-derived observations.
- CNAME-chain candidate discovery.
- Private-run disclosure controls.
- Public-source-backed catalog promotion.

The no-CT calibration pass already covers the nine Bayesian nodes that are fed
by DNS and identity endpoints. CT contributes mostly to certificate,
infrastructure-cluster, lexical, and surface-attribution work. That is why the
track was valuable, and also why it could not block release forever waiting for
perfect CT coverage.

## Code Constraints

The current implementation sets the execution shape:

- `validation/scan.py --ct` runs `recon batch` with streaming NDJSON by default.
- `--max-runtime` finalizes a partial run instead of relying on an external kill.
- `--finalize-existing` recovers a run without network access.
- `--ct-retry-from` synthesizes a private retry corpus from degraded
  `ct_attempt_outcome` records only, validates those domains, and writes the
  retry input under `validation/runs-private/_inputs/`.
- `validation/summarize_ct_sessions.py` emits aggregate counts only and rejects
  in-repo paths outside private validation roots.
- `scripts/check_validation_hygiene.py` rejects tracked private validation
  artifacts and target-domain fields in committed validation memos.

These constraints are correct. Do not bypass them with shell redirects, public
run roots, ad hoc JSON edits, or row-level summaries.

## Closure Decision

The certificate-transparency validation track is closed as a documented partial
CT pass.

The reason to close is not that CT coverage is complete. It is not. The
reason is that the track has met the validation objective that justified live
public CT work:

- CT collection, cache fallback, degraded-source reporting, and retry synthesis
  were exercised across seven sessions.
- The aggregate summary now tracks unique-domain CT coverage across partial
  sessions instead of raw retry counts.
- Provider limits are explicit: free public search paths provide small,
  cooldown-bound increments and crt.sh can remain unavailable or breaker-gated.
- Candidate promotion discipline was exercised twice in the full
  certificate-transparency track:
  Descope from Session C and Infobip from Session E. Both changes have public
  vendor references, narrow suffix rules, negative boundary tests, and taxonomy
  checks.
- Session F, the post-promotion check, produced no new candidates. Continuing
  live retries would spend operator time mainly measuring the same public
  provider ceiling.

Final public-tree work completed before closure:

1. Update the aggregate certificate-transparency memo and roadmap with Sessions
   D, E, and F.
2. Keep raw run outputs, retry inputs, candidate samples, and target rows under
   ignored private validation paths only.
3. Run the focused fingerprint and taxonomy tests.
4. Run text hygiene, validation hygiene, release-readiness checks, and the full
   local gate.
5. Commit and push only after the gate passes.

Do not run Session G by default. A future live certificate-transparency retry
requires a new concrete reason: a different free public provider path, a named
consumer needing another aggregate metric, or a disclosure-safe validation
question that cannot be answered from the seven-session summary.

## Out Of Scope For This Track

- Adding a paid CT provider or API key.
- Adding a direct Static CT monitor.
- Building a persistent aggregate CT database.
- Publishing private target rows or small strata.
- Expanding stable JSON, CLI, or MCP surfaces.
- Treating CT-derived related domains as ownership claims.

Those may be future proposals only if they pass the roadmap invariants and have
a concrete consumer. They are not next.

## Required Gates

Before committing any certificate-transparency follow-up:

```bash
python scripts/check_validation_hygiene.py
python scripts/check_text_hygiene.py
python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints --quiet
python scripts/check.py
```

If catalog code changes, also run focused tests for the touched detector,
taxonomy, and formatter paths before the full gate.
