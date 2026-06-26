# C3 CT Validation Plan

This is the current maintainer plan for finishing the CT-enabled C3 corpus
track. It turns the roadmap item into an executable sequence without changing
recon's runtime surface.

The plan is intentionally bounded. CT is a public monitoring system and a useful
source of certificate and subdomain evidence, but it is not a free bulk data
warehouse. C3 should prove recon's CT paths, graph surfaces, retry accounting,
and catalog-triage discipline under real provider constraints. It should not
try to force complete CT coverage through public search endpoints.

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
  release is a governed disclosure process, not a string-redaction trick. C3
  memos must remain counts-only, suppress small cells, and avoid rows.
- [Diataxis](https://diataxis.fr/): keep orientation, task guidance, reference,
  and explanation separated. That is why this plan lives outside the README and
  why the roadmap points here instead of carrying command-level details.
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
  [Semantic Versioning](https://semver.org/): C3 updates belong under
  `Unreleased`; patch-line work must avoid new stable runtime surfaces.

## Current State

The C3 CT track has four private sessions documented in
[../validation/2026-06-26-c3-ct-partial.md](../validation/2026-06-26-c3-ct-partial.md).

Aggregate state:

- Sessions summarized: 4.
- Valid records across sessions: 2,869.
- Records with a domain field: 2,836.
- Unique domains observed across sessions: 2,647.
- Domains with CT data: 40.
- CT-data coverage ratio: 0.015111.
- Domains still degraded or unresolved for CT: 2,607.
- External spend: 0 USD.

What changed in the latest cycle:

- Retry Session C completed the 33 degraded records from Retry Session B.
- One more domain obtained usable CT data.
- One private candidate was promoted only after public-source review and tests:
  Descope custom-domain CNAME targets.
- The `descope` slug now maps to the Identity panel category and exposure
  identity-provider view.

## Why This Is Next

C3 remains the top roadmap item because it is the only current task that
exercises all of these surfaces together:

- CT provider failure modes and cache fallback.
- CT attempt-outcome accounting.
- Certificate and graph-derived observations.
- CNAME-chain candidate discovery.
- Private-run disclosure controls.
- Public-source-backed catalog promotion.

The no-CT calibration pass already covers the nine Bayesian nodes that are fed
by DNS and identity endpoints. CT contributes mostly to certificate,
infrastructure-cluster, lexical, and surface-attribution work. That is why C3 is
valuable, and also why it must not block release forever waiting for perfect CT
coverage.

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

## Execution Plan

### 1. Provider Health Check

Before any new CT network run:

```bash
recon doctor
python validation/summarize_ct_sessions.py \
  validation/runs-private/20260626-114954Z \
  validation/runs-private/20260626-155208Z \
  validation/runs-private/20260626-171647Z \
  validation/runs-private/20260626-191156Z \
  --output validation/runs-private/c3-ct-session-summary-20260626.json
```

Also inspect the local limiter snapshots under the operator config directory:

```text
<recon config>/rate-limit-state/
```

Proceed only if at least one CT provider is not in a long breaker window. If
every provider is still gated, do not run another live scan. Update the memo with
a no-network provider-health note and wait for cooldown.

### 2. Retry Session D

If provider health permits, retry only the degraded tail from Retry Session C:

```bash
python validation/scan.py \
  --corpus validation/corpus-private/consolidated.txt \
  --ct-retry-from validation/runs-private/20260626-191156Z \
  --ct \
  --concurrency 1 \
  --timeout 60 \
  --max-runtime 300 \
  --no-compare \
  --label c3-ct-retry-d
```

Why this exact shape:

- `--ct-retry-from` keeps the run focused on the 32-record degraded tail instead
  of re-querying successful records.
- `--concurrency 1` respects free public provider limits.
- `--timeout 60` gives slow CT lookups enough room without consuming the whole
  operator session.
- `--max-runtime 300` is enough for the current tail and keeps failure bounded.
- `--no-compare` avoids noisy diffs between partial and complete scans.

If the retry corpus grows unexpectedly, stop and inspect why before proceeding.

### 3. Rebuild Aggregate Summary

After Session D, rebuild the private aggregate summary across all C3 sessions:

```bash
python validation/summarize_ct_sessions.py \
  validation/runs-private/20260626-114954Z \
  validation/runs-private/20260626-155208Z \
  validation/runs-private/20260626-171647Z \
  validation/runs-private/20260626-191156Z \
  validation/runs-private/<session-d> \
  --output validation/runs-private/c3-ct-session-summary-20260626.json
```

Then update only aggregate public docs:

- `validation/2026-06-26-c3-ct-partial.md`
- `docs/roadmap.md`
- `CURRENT-STATE-ANALYSIS.md`
- `CHANGELOG.md`
- `QUALITY-RUBRIC.md`
- `PROGRESS-LOG.md`

Do not publish target rows, example domains from the private corpus, tenant IDs,
or raw candidate rows.

### 4. Candidate Triage

For any candidate from Session D:

1. Confirm the observed target with public vendor documentation or repeated
   aggregate-safe evidence.
2. Add the narrowest `cname_target` or TXT rule that matches the documented
   product endpoint.
3. Add a negative boundary test for lookalike suffixes.
4. Add category and display-name taxonomy updates if the slug is not generic
   Business Apps.
5. Run `scripts/validate_fingerprint.py` and the relevant focused tests.

Reject candidates that have no public support, are intra-organization routing,
or would require broad suffix matching.

### 5. Closure Decision

After Session D, C3 should either close as a documented partial CT pass or name
one additional bounded retry. Use this decision rule:

- Close C3 if Session D produces zero new CT-data domains and no
  public-source-backed candidates.
- Close C3 if providers remain rate-limited after cooldown and the aggregate
  memo already documents the limiter ceiling.
- Continue for one more bounded retry only if Session D produces new CT data or
  a candidate that materially improves catalog coverage.

Closure does not mean "100 percent CT coverage." It means recon has exercised
the CT path, documented provider limits, published aggregate-safe evidence, and
resolved all promoted candidates through tests and public references.

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

Before committing any C3 follow-up:

```bash
python scripts/check_validation_hygiene.py
python scripts/check_text_hygiene.py
python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints --quiet
python scripts/check.py
```

If catalog code changes, also run focused tests for the touched detector,
taxonomy, and formatter paths before the full gate.
