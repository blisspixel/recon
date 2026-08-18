# validation/

Live-validation workspace. The directory hosts the runners, the gap-analysis
tooling, and the fingerprint-discovery loop, plus a small reserved-example
corpus. Real-target corpora and per-domain outputs belong only in the ignored
private workspaces described below. Git ignore rules protect those paths, not a
real name copied into an arbitrary tracked file; see [Policy](#policy) below.

## What's in here

Committed (generic tooling, no company names):

- `run_corpus.py`: batch runner. Calls `recon` across a corpus file, emits
  `results.json`, `summary.json`, `summary.md` per run.
- `find_gaps.py`: reads a run (single file or directory of per-domain JSON)
  and surfaces unclassified CNAME terminal suffixes ranked by frequency. The
  first half of the fingerprint-discovery loop.
- `catalog_baseline.py`: reduces nested JSON or NDJSON opt-in typed DNS
  diagnostics into a
  private evidence queue, a private revision manifest, and a separate
  aggregate-only coverage report. It covers every bounded catalog record path
  and never writes a queried namespace into the aggregate report. Schema 1.2
  reports measured inputs separately from validation, timeout, and lookup
  errors.
- `agent_portability_contract.py`: validates the frozen, disclosure-safe v2.15
  representative-client contract, exact standards commitments, client and task
  frame, privacy boundary, and promote-or-defer thresholds without network
  access.
- `prepare_agent_portability_evaluation.py`: validates the frozen contract and
  current candidate, records exact local client and recon versions privately,
  and stops before session collection when a required client or runtime gate is
  unavailable. It makes no network request.
- `../scripts/generate_agent_plugin.py`: derives the complete portable
  candidate deterministically from the native skill sources and package
  version; `--check` rejects drift.
- `../scripts/check_agent_plugin.py`: validates the exact candidate file set,
  byte-pinned v1.0.0 schemas, explicit stdio launch, portable skill fields,
  package bounds, and qualified claim boundary without network access.
- `prepare_catalog_round.py`: validates a private round plan, reduces every
  input to a unique registrable apex, and exclusively writes an integrity-bound
  normalized frame plus its frozen manifest. It performs no network requests.
- `prepare_catalog_rank_frame.py`: derives the exact four private Tranco rank
  strata with secret-keyed sampling and whole-development-corpus exclusion.
  Its console output contains aggregate counts and commitments only.
- `prepare_catalog_region_frame.py`: derives five private ccTLD-delegation
  strata from a frozen ranked source and a pinned IANA / UN M49 intersection.
  It uses equal secret-keyed discovery quotas, excludes every declared prior
  corpus, performs no network requests, and never treats a ccTLD as evidence of
  an organization's location.
- `prepare_catalog_region_sources.py`: makes exactly two bounded HTTPS requests
  to the official IANA and UN M49 pages, archives the raw responses privately,
  and derives their exact ASCII ccTLD intersection. It contacts no sampled
  namespace and prints only aggregate counts and cryptographic commitments.
- `archive_vendor_seed_sources.py`: sequentially archives only exact HTTPS
  pages under predeclared provider domains. It refuses redirects, credentials,
  compression, retries, unsafe hosts, unexpected media types, and oversized
  responses; writes a private receipt atomically; and prints no URL or target
  identifier.
- `stratify_catalog_round.py`: reconstructs frozen private membership, assigns
  every completed result exactly once, and writes ordered per-stratum typed
  aggregates without exposing stratum labels or namespaces.
- `prepare_vendor_seed_round.py`: validates a private provider-controlled
  source dossier, excludes every declared prior frame, binds every holdout
  member to an archived source, and emits a generic vendor-seed round contract
  without contacting a target or printing an identifier.
- `evaluate_vendor_seed_round.py`: binds complete scan results to the frozen
  source, membership, pooled-aggregate, catalog, and implementation contracts,
  then writes provider-level corroborated, observed-silent, unavailable,
  unmeasured, and error counts with Wilson intervals. Silence is not scored as
  a false negative.
- `triage_candidates.py`: programmatic filter on `gaps.json`: drops
  already-fingerprinted patterns, intra-org chains, and one-off noise. The
  output is the LLM-triage-ready candidate list.
- `diff_runs.py`: compares two run directories. Surfaces newly-attributed
  subdomains, lost slugs, and aggregate slug-frequency changes. Use after
  adding fingerprints to confirm uplift.
- `run_calibration_bundle.py`: maintainer-local wrapper around the reference,
  tenancy, and conformal re-split diagnostic harnesses. Captures aggregate JSON without
  shell redirects and renders the checked memo under `runs-private/`.
- `audit_fingerprints.py`: no-network catalog audit. Reports metadata
  coverage and match-mode classification (`keep_any`, `review_for_all`,
  `tighten_patterns`).
- `render_calibration_memo.py`: reads aggregate JSON from private calibration
  runs, rejects target-identifying fields or unsuppressed small strata, and
  renders a reviewable aggregate memo.
- `reproduce_paper_numbers.py`: one-command public reproduction bundle for the
  paper's no-private-data numbers. It runs existing synthetic/proof harnesses and
  writes local artifacts under `validation/local/`.
- `corpus-example.txt`: numbered `.invalid` scenarios showing the format
  without implying a company or querying a live namespace.

Gitignored (your private workspace):

- `corpus-private/`: your curated test bed of real apexes, organized however
  you want (by region, vertical, customer type)
- `runs-private/`: output dirs from each run (results, gaps, diffs)
- `live_runs/`: default output from `run_corpus.py`
- `local/`: any other scratch space (notes, half-finished YAMLs, etc.)
- `agent-portability-local/`: v2.15 client run records and transcripts; never a
  public result source

## Agent-portability candidate and preregistration

The frozen public contract passed protected main before candidate work began.
The complete-surface candidate is now generated under `agents/agent-plugin/`
and passes offline validation. Reproduce both boundaries before any client
collection:

```bash
uv run python -m validation.agent_portability_contract
uv run python scripts/generate_agent_plugin.py --check
uv run python scripts/check_agent_plugin.py
```

The declaration is
[`docs/agent-portability-evaluation-declaration.md`](../docs/agent-portability-evaluation-declaration.md).
The validators are network-free and print only aggregate package state, the
contract digest, and frame counts. Offline validation is not a compatibility claim.
Client session records stay under the ignored
`validation/agent-portability-local/` workspace. Do not commit transcripts,
hidden reasoning, credentials, client state, or per-session responses.

Before any client session, run the fail-closed preflight with the absolute recon
executable path that the desktop clients will resolve. Do not pass bare
`recon` from inside `uv run`: its temporary project environment may differ from
the desktop-client launch environment.

```bash
uv run python -m validation.prepare_agent_portability_evaluation \
  --runtime-command /absolute/path/resolved-by-the-clients/recon \
  --output validation/agent-portability-local/<unique-run>/preflight.json
```

The output is exclusive and private. The command starts no client session,
makes no network request, and prints no executable path. Exit 0 means the
frozen frame is ready to begin; exit 3 means a stop rule applied. The first
maintainer-local aggregate result is recorded in
[`2026-08-14-agent-portability-preflight.md`](2026-08-14-agent-portability-preflight.md):
Cursor was unavailable and the selected client-launch recon was 2.6.3 rather
than 2.14.0, so collection correctly stopped with zero sessions.

## The fingerprint-discovery loop

```
USER runs recon on a target (single domain or corpus)
    ↓
RECON emits opt-in JSON with count-only typed coverage and unmatched values
    ↓
PRIVATE REDUCER separates aggregate counts from evidence-bearing candidate rows
    ↓
PROGRAMMATIC FILTER drops same-zone, already-classified, and one-off noise
    ↓
LLM SKILL judges each survivor: real SaaS? tier? slug? category? YAML stanza?
    ↓
USER reviews, applies surface.yaml diff
    ↓
RECON re-runs the corpus, confirms uplift via diff_runs.py
```

Two entry points feed the same triage logic:

### Single-domain (incidental discovery during normal use)

```bash
recon discover scenario.example.invalid \
    --output validation/local/scenario-candidates.json
```

`recon discover` performs the same lookup, bucketing, and existing-pattern and
same-zone filtering without leaving a raw result in the repository root. For a
real target, keep both the output path and any follow-up notes under
`validation/local/` or another ignored private workspace. Then hand the private
candidate file to the
[`/recon-fingerprint-triage`](../agents/claude-code/skills/recon-fingerprint-triage/SKILL.md)
skill, or to any agent reading the same input shape.

### Corpus run (deliberate, batch)

```bash
# Build (once) a private corpus
mkdir -p validation/corpus-private/
echo "scenario.example.invalid" > validation/corpus-private/saas-b2b.txt
# ... add more domains, organize as you like ...

# Run respectfully: concurrency 2 stays well under crt.sh's tolerance
python validation/run_corpus.py \
    --corpus validation/corpus-private/saas-b2b.txt \
    --concurrency 2 \
    --exclude-results validation/runs-private/<prior-run>/ \
    --limit 200

# Aggregate gaps across the run
python validation/find_gaps.py \
    --input validation/live_runs/<UTC-stamp>/ \
    --output validation/runs-private/<run>/gaps.json

# Filter to triage candidates
python validation/triage_candidates.py \
    --gaps validation/runs-private/<run>/gaps.json \
    --fingerprints src/recon_tool/data/fingerprints/ \
    --output validation/runs-private/<run>/candidates.json \
    --min-count 2 \
    --min-distinct-namespaces 2

# After adding fingerprints, verify uplift
python validation/diff_runs.py \
    --before <previous-run>/ \
    --after <new-run>/ \
    --output diff.json
```

### Polite-mode knobs for big runs

Both `recon` and `run_corpus.py` accept these:

- `--no-ct`: skip cert-transparency providers entirely. Discovery falls back
  to common-subdomain probes + apex CNAME walks. Use for runs of 1000+ domains
  where you want zero load on public CT services.
- `--concurrency N` (on `run_corpus.py`): how many `recon` invocations run in
  parallel. Default is 5; drop to 2 for large runs to stay polite to CT and
  DNS.

### Monthly cadence with `scan.py`

When you want to track catalog drift over time (e.g. "is recon's coverage
of our regional banks decaying?"), use the `scan.py` wrapper. It bundles
`recon batch` + `find_gaps` + `triage_candidates` + `diff_runs` into a
single timestamped invocation:

```bash
# First run of the month (writes to validation/runs-private/<UTC-stamp>/)
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label monthly-2026-05 \
    --round-kind baseline \
    --concurrency 4

# Next month: compare only against the explicitly frozen prior scan
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label monthly-2026-06 \
    --round-kind drift \
    --round-manifest validation/corpus-private/drift-2026-06-manifest.json \
    --drift-prior-contract validation/corpus-private/drift-2026-06-prior-contract.json \
    --compare-to validation/runs-private/<exact-prior-run>
```

Independent rank, region, vertical, vendor-seed, and drift rounds require a
frozen manifest before collection. Start with a private JSON plan containing a
round identifier and question, source name and revision, one or more named
strata with private input paths, exclusion and overlap policies, CT and direct
probe settings, recurrence thresholds, and a promotion/regression budget. Then
prepare the exact corpus and manifest without contacting a target:

For the rank round, first create and freeze the four independent Tranco strata.
The plan must declare the exact 1-1k, 1k-10k, 10k-100k, and 100k-1M ranges and
the same explicit discovery quota for every band:

```bash
python -m validation.prepare_catalog_rank_frame generate-key \
    --output validation/corpus-private/catalog-rank-key.hex

python -m validation.prepare_catalog_rank_frame prepare \
    --plan validation/corpus-private/catalog-rank-selection-plan.json \
    --output-directory validation/corpus-private/catalog-rank-selection \
    --preflight

python -m validation.prepare_catalog_rank_frame prepare \
    --plan validation/corpus-private/catalog-rank-selection-plan.json \
    --output-directory validation/corpus-private/catalog-rank-selection \
    --write-private-strata
```

The keyed rule uses a separate domain-separation context for every band. The
equal quota is a discovery budget, not population weighting or a prevalence
estimator. Commit the aggregate-only selection declaration before collection.
Then reference the four private outputs from the ordinary round plan:

```bash
python -m validation.prepare_catalog_round \
    --plan validation/corpus-private/rank-2026-08-plan.json \
    --output-corpus validation/corpus-private/rank-2026-08-frame.txt \
    --output-manifest validation/corpus-private/rank-2026-08-manifest.json

python validation/scan.py \
    --corpus validation/corpus-private/rank-2026-08-frame.txt \
    --round-kind rank \
    --round-manifest validation/corpus-private/rank-2026-08-manifest.json \
    --concurrency 4
```

The regional round uses the same two-stage discipline. First freeze the raw
official pages and derive the private mapping. This step makes two fixed-source
requests, one to IANA and one to UN M49, but contacts no sampled namespace. It
fails closed on any redirect, non-HTML or oversized response, table-schema
drift, duplicate codes, implausible source size, or an existing output artifact:

```bash
python -m validation.prepare_catalog_region_sources \
    --output-directory validation/corpus-private/catalog-region-sources
```

The generated CSV has the exact columns
`tld,iana_type,iso_alpha2,region_code,region_name`. Rows are the ASCII
two-letter intersection of IANA `country-code` TLDs and UN M49 ISO alpha-2
entries in the five canonical M49 regions. Regionless entries such as
Antarctica are counted and excluded explicitly. Pin the mapping revision and
digest from the private source manifest in the selection plan. The frame
preparer then chooses the largest eligible ccTLD universes within each region
and takes the same secret-keyed discovery quota from every selected ccTLD:

```bash
python -m validation.prepare_catalog_rank_frame generate-key \
    --output validation/corpus-private/catalog-region-key.hex

python -m validation.prepare_catalog_region_frame \
    --plan validation/corpus-private/catalog-region-selection-plan.json \
    --output-directory validation/corpus-private/catalog-region-selection \
    --preflight

python -m validation.prepare_catalog_region_frame \
    --plan validation/corpus-private/catalog-region-selection-plan.json \
    --output-directory validation/corpus-private/catalog-region-selection \
    --write-private-strata
```

This is a ccTLD namespace comparison, not geolocation. Equal region and ccTLD
quotas are discovery budgets, not population weights. Globally marketed ccTLDs
remain grouped by their IANA delegation and UN M49 area, so the result cannot
support claims about registrant location, organizational presence, or regional
Internet prevalence. Commit the aggregate-only selection declaration and merge
its implementation before any selected namespace is contacted.

The completed v2.14 regional contract is frozen in the
[public declaration](../docs/catalog-regional-round-declaration.md). Its
official source, mapping, selection, frame, catalog, implementation, collection,
and decision commitments were published before any selected-namespace request.
The aggregate-only
[result](2026-08-13-catalog-regional-round.md) records the complete baseline,
accepted fixed-observation decision, and clean protected-main replay. The
regional round is closed. The fail-closed vendor-seed protocol is published in
the [public declaration](../docs/catalog-vendor-seed-round-declaration.md).
Its receipt-bound dossier, 17,952-namespace exclusion union, and 33-row
disjoint HubSpot frame produced the closed aggregate-only
[result](2026-08-14-catalog-vendor-seed-round.md): 29 corroborated, 4
observed-silent, no unavailable, unmeasured, or error outcome, and no catalog
promotion. The final 5,199-row prior-sample
[drift result](2026-08-14-catalog-drift-round.md) is also closed: all rows were
measured, no record type breached the frozen decline threshold, the
catalog-driven measurement-surface change is explicit, classification
comparison is withheld, and no rule was promoted. Its exact disclosure-safe
[aggregate](2026-08-14-catalog-drift-aggregate.json) is committed.

### Frozen prior-sample drift

A drift round has two immutable inputs: the future generic round manifest and
the exact retained prior result. Extract the previously measured canonical
rows directly from the prior result without printing identifiers:

```bash
python -m validation.prepare_catalog_drift_round \
    --prior-run validation/runs-private/<exact-prior-run> \
    --output-frame validation/corpus-private/<drift>/prior-frame.txt \
    --public
```

Use that generated file as the only stratum in an ordinary schema-version-2
drift plan, then prepare the current frame and manifest. Finally bind the
prior result, prior aggregate, prior catalog and collection settings, eligible
frame, and current manifest into the comparison sidecar:

```bash
python -m validation.prepare_catalog_round \
    --plan validation/corpus-private/<drift>/round-plan.json \
    --output-corpus validation/corpus-private/<drift>/frame.txt \
    --output-manifest validation/corpus-private/<drift>/round-manifest.json

python -m validation.prepare_catalog_drift_round \
    --prior-run validation/runs-private/<exact-prior-run> \
    --round-manifest validation/corpus-private/<drift>/round-manifest.json \
    --output validation/corpus-private/<drift>/prior-contract.json \
    --public
```

For a future round, commit only the identifier-free declaration and
implementation, pass protected main, and then run the exact contract once:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/<drift>/frame.txt \
    --round-kind drift \
    --round-manifest validation/corpus-private/<drift>/round-manifest.json \
    --drift-prior-contract validation/corpus-private/<drift>/prior-contract.json \
    --compare-to validation/runs-private/<exact-prior-run> \
    --min-count 3 \
    --concurrency 4

python -m validation.evaluate_catalog_drift_round \
    --contract validation/corpus-private/<drift>/prior-contract.json \
    --after validation/runs-private/<new-run> \
    --output validation/runs-private/<new-run>/drift-aggregate.json
```

`scan.py` rejects drift without both the sidecar and explicit prior, rejects
`--no-compare`, and verifies every prior and current commitment before the
batch process starts. The evaluator requires every frozen row exactly once and
reports `changed`, `unavailable`, `unmeasured`, and `no_change` by bounded
record type. It compares only retained `availability`, `opportunity_count`,
`observed_count`, and `truncated` fields. Classified counts and detected slugs
are comparable only when both the prior and current catalog and
interpretation-execution digests match. A `no_change` outcome therefore means
no retained summary change, not identical DNS, complete zone equality, or
stable product use.

The steps below document the reusable protocol and its reproduction boundary;
they are not instructions to replace the current frozen contract. A
vendor-seed dossier uses only provider-controlled HTTPS evidence as its
relationship label. Create a strict private source plan with
`schema_version`, `private`, `source_set_id`, a meaningful `purpose`, and one
or more `providers`. Each provider names an existing release-bound built-in
catalog `slug`, one or more `allowed_domains`, and exact sources with `id`,
`url`, and `expected_media_type`. Operator-local custom and process-local
ephemeral fingerprints are ineligible because the public catalog commitment
does not bind them. Declaring an allowed registrable domain is a curator
assertion that it is provider-controlled; the tool enforces host containment
but cannot establish corporate ownership.

Example source-plan shape using a public provider citation and no customer
identity:

```json
{
  "schema_version": 1,
  "private": true,
  "source_set_id": "vendor-seed-sources-2026-08",
  "purpose": "Archive exact provider-controlled customer evidence before freezing the disjoint vendor-seed frame.",
  "providers": [
    {
      "slug": "shopify",
      "allowed_domains": ["shopify.com"],
      "sources": [
        {
          "id": "customer-evidence",
          "url": "https://www.shopify.com/case-studies",
          "expected_media_type": "text/html"
        }
      ]
    }
  ]
}
```

Archive the plan before extracting any customer membership:

```bash
python -m validation.archive_vendor_seed_sources \
    --plan validation/corpus-private/vendor-seed/source-plan.json \
    --output-dir validation/corpus-private/vendor-seed/frozen-sources
```

The freezer makes one sequential GET per declared source, with no redirects,
credentials, compression, or retry. It accepts only the declared HTML, XHTML,
PDF, text, or JSON media type, caps each response at 10 MiB and the full set at
128 MiB, and atomically writes the exact `source-plan.json`, `receipt.json`,
and archived bytes. The loader verifies the plan and implementation digests
before the dossier can use the receipt. Its console output contains only
counts and digests. This is provider-source
collection, not selected-namespace collection; `selected_target_requests`
remains zero.

Build the private schema-version-2 dossier from that immutable receipt. Its
`source_receipt` field points to `receipt.json`; every dossier source must match
the receipt's provider slug, source ID, URL, retrieval time, archive path, byte
count, and digest exactly. Each member is bound to an archived source ID, every
stratum has at least 20 unique apexes, and the exclusion union covers
development and every earlier observation or case-study frame. Customer
identities, archived pages, source mappings, and exclusion rows remain private.
Prepare the schema-version-2 contract with zero target requests:

```bash
python -m validation.prepare_vendor_seed_round \
    --dossier validation/corpus-private/vendor-seed/dossier.json \
    --output-dir validation/corpus-private/vendor-seed/frozen-contract
```

Copy only aggregate counts and commitments into the public declaration, merge
that declaration and the exact implementation through protected main, and
only then run the frozen frame. For the completed contract those commitments
were recorded before collection, CT was disabled, and direct CSE and BIMI
probes were off. The commands below reproduce the exact invocation shape; a
later repeated collection is drift evidence, not a second independent
vendor-seed result.

```bash
python validation/scan.py \
    --corpus validation/corpus-private/vendor-seed/frozen-contract/frame.txt \
    --round-kind vendor-seed \
    --round-manifest validation/corpus-private/vendor-seed/frozen-contract/round-manifest.json \
    --min-count 2 \
    --concurrency 2

python -m validation.evaluate_vendor_seed_round \
    --input validation/runs-private/<run>/results.ndjson \
    --round-plan validation/corpus-private/vendor-seed/frozen-contract/round-plan.json \
    --round-manifest validation/corpus-private/vendor-seed/frozen-contract/round-manifest.json \
    --source-contract validation/corpus-private/vendor-seed/frozen-contract/source-contract.json \
    --pooled-aggregate validation/runs-private/<run>/catalog-aggregate.json \
    --output-dir validation/runs-private/<run>/vendor-seed-evaluation
```

The denominator is `corroborated + observed_silent` within each provider.
Unavailable, unmeasured, and error rows are reported separately. A
provider-controlled customer relationship does not guarantee that a particular
DNS record is published on the queried apex, so this is a relationship
corroboration rate, not recall, precision, prevalence, or a false-negative
rate. Do not pool provider strata into a population estimate or tune a rule
from its holdout outcome.

Preparation fails closed on malformed rows, undeclared fields, cross-stratum
overlap contrary to policy, direct-probe requests, or existing output files.
Before target contact, `scan.py` revalidates the manifest digest, normalized
frame digest and count, stratum counts, collection options, and recurrence
thresholds. Schema-version-2 contracts also commit the source catalog and a
digest of the execution code, package data, project metadata, and dependency
lockfile. `scan.py` rejects catalog or implementation drift before target
contact. The typed reducer repeats the contract checks and binds every result
row to the frozen frame. The reviewable aggregate contains counts, fixed
options, and cryptographic commitments only. Descriptive questions, source and
stratum labels, policies, decision prose, identifiers, and paths remain in the
private manifest.

Each run directory ends up with `results.ndjson` by default (`results.json`
with `--json-array`), `gaps.json`, `candidates.json`, `catalog-gaps.json`,
`catalog-aggregate.json`, `catalog-manifest.json`, `diff.json` (when comparing
to a prior run), and `meta.json`. The manifest and gap files remain private.
The aggregate file contains only counts, digests, revision metadata, and
environment details and must still be reviewed before any number is copied
into a committed memo. `meta.json` captures the scan timestamp, round kind,
label, raw input rows, normalized scheduled count, duplicate and malformed-row
counts, and candidate counts.
Reading `meta.json` from any run answers "when was this scanned, what was
found?" without re-running.

A pooled aggregate does not answer a multi-stratum question. After a complete
rank, regional, or vertical run, bind the original private plan, manifest,
results, and pooled aggregate into an ordered stratified reduction:

```bash
python validation/stratify_catalog_round.py \
    --input validation/runs-private/<run>/results.ndjson \
    --round-plan validation/corpus-private/<round>-plan.json \
    --round-manifest validation/corpus-private/<round>-manifest.json \
    --pooled-aggregate validation/runs-private/<run>/catalog-aggregate.json \
    --output-dir validation/runs-private/<run>
```

The reducer rejects source or plan drift, incomplete, duplicate, or out-of-frame
results, a mismatched pooled aggregate, and existing output artifacts. Its
public file uses only `stratum_index` in the frozen manifest order, aggregate
typed counts, and commitments. Labels, membership, and candidate evidence stay
in the private files. Public stratification also fails closed below 20 rows in
any stratum; a smaller holdout needs a separately reviewed suppression rule.
The historical observation execution digest remains
separate from the later stratified-reducer digest so a new interpretation does
not masquerade as the code that collected the observations.

When a live replay differs because public DNS changed between passes, evaluate
the additive catalog effect against the exact retained baseline observations:

```bash
python validation/evaluate_catalog_promotions.py \
    --input validation/runs-private/<baseline>/results.ndjson \
    --round-plan validation/corpus-private/<round>-plan.json \
    --round-manifest validation/corpus-private/<round>-manifest.json \
    --pooled-aggregate validation/runs-private/<baseline>/catalog-aggregate.json \
    --candidate-slug <slug> \
    --output validation/runs-private/<baseline>/catalog-promotion-counterfactual.json
```

Repeat `--candidate-slug` for a batch. The evaluator accepts only referenced,
dated DNS-label suffix rules for `mx`, `ns`, `spf`, and `cname_target`. It binds
the complete frozen membership and baseline result digest, uses the original
observed denominators, and emits aggregate counts only. Report this causal
counterfactual separately from the live replay. A later DNS change is neither a
catalog regression nor catalog uplift.

For large monthly cadence, keep `--no-ct` on unless CT coverage is the point and
use modest concurrency. Real-company corpora live entirely under
`validation/corpus-private/` and never leave your machine; only generic patterns
surfaced for triage become candidate PRs.
If `--output-root` is inside this checkout, it must resolve under one of the
gitignored private validation workspaces: `validation/runs-private/`,
`validation/live_runs/`, or `validation/local/`. Operator-local paths outside
the checkout are allowed.

Certificate-transparency corpus sessions are intentionally partial and
multi-session. Use streaming NDJSON plus a wall-clock cap so a session finalizes
aggregate artifacts instead of being killed by the terminal or CI wrapper:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label c3-ct-session-1 \
    --ct \
    --concurrency 2 \
    --timeout 60 \
    --max-runtime 7200 \
    --no-compare
```

`--exclude-results` may be repeated. It reads JSON arrays and streamed NDJSON,
including nested scan directories, canonicalizes and removes namespaces already
present in prior result files, then stores the filtered input manifest inside
the ignored output directory. Use it when private strata overlap so a pooled
round does not count the same queried namespace twice.
`--limit` applies after normalization, exclusion, and deduplication, making
fixed-size sequential rounds from a larger frozen private stratum reproducible.

If a process was interrupted after `results.ndjson` already streamed records,
recover the aggregate artifacts without touching the network:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --finalize-existing validation/runs-private/<UTC-stamp> \
    --ct \
    --no-compare
```

Partial runs write `meta.json` with `batch_completed`, `batch_timed_out`,
`results_records`, and the timeout settings. Diffing is skipped for partial
runs because comparing a partial session against a complete prior run is noisy.

After the public CT limiter cools down, retry only the domains whose CT attempt
was degraded in a prior session:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --ct-retry-from validation/runs-private/<UTC-stamp> \
    --label c3-ct-retry-1 \
    --concurrency 2 \
    --timeout 60 \
    --max-runtime 7200 \
    --no-compare
```

The synthesized retry corpus is written under
`validation/runs-private/_inputs/` by default, keeping private apexes inside the
ignored validation workspace. `--ct-retry-from` accepts a run directory,
`results.ndjson`, or legacy `results.json`; malformed streamed tails are skipped
and repeated domains are retried once.

To understand progress across partial sessions without exposing target rows,
summarize private runs into aggregate JSON:

```bash
python validation/summarize_ct_sessions.py \
    validation/runs-private/<session-a> \
    validation/runs-private/<session-b> \
    --output validation/runs-private/c3-ct-session-summary.json
```

The summary reports raw outcome counts, best outcome by unique domain, and CT
data coverage. It emits run directory basenames and counts only. It does not
write domains, tenant IDs, organization names, or per-domain rows.

The 2026-06-26 certificate-transparency sequence is closed and documented in
[docs/c3-ct-validation-plan.md](../docs/c3-ct-validation-plan.md) and
`validation/2026-06-26-c3-ct-partial.md`. Do not use the old retry order as an
active queue unless a new concrete provider path or disclosure-safe validation
question changes the value calculation. Current publication packaging work is
tracked in [docs/external-writeup-plan.md](../docs/external-writeup-plan.md).

## Assurance and calibration harnesses

The statistical-assurance side of this directory (the dossier that reads
them: [docs/statistical-assurance.md](../docs/statistical-assurance.md)).
Synthetic harnesses run anywhere and their committed memos carry real
numbers; reference harnesses resolve real apexes, so their runs stay
maintainer-local and emit aggregates only
([docs/data-handling-policy.md](../docs/data-handling-policy.md)).

Synthetic / no-network (runnable by anyone, deterministic):

- `synthetic_calibration.py`: model-grounded calibration: samples worlds
  from the network's own priors/CPTs and checks reliability, ECE, Brier.
- `interval_coverage.py`: the v2.1.15 finite perturbation-containment gate for
  the 80% model-relative uncertainty band against selected likelihood scenarios.
  This is not empirical or Bayesian interval coverage. Memo:
  `interval-coverage.md`.
- `differential_verification.py`: variable elimination cross-checked
  against naive full-joint enumeration over the enumerable evidence sweep.
- `adversarial_properties.py`: the machine-checked local suppression property
  under fixed positive-factor assumptions (correlation.md section 3.4).
- `adversarial_corpus/`: the record-layer complement to the above. Hand-authored
  `.invalid` DNS record sets replayed end to end through the shipped record-role
  gate into inference, measuring the Pattern I planted-administrative-token vector
  (correlation.md section 4.11). Run and committed (fully offline): 0 of 7
  administrative-only plants moved a gated node to supported. Memo:
  `2026-08-17-adversarial-corpus-round.md`.
- `likelihood_sensitivity.py`: CAL8: posteriors/agreement under ±20%
  likelihood perturbation. Memo: `cal8-likelihood-sensitivity.md`.
- `drift_check.py`: the PV2 inference drift gate against
  `inference_baseline.json` (CI-gated).
- `layer_ablation.py`: what each layer adds: the Bayesian posterior vs
  slug-matching baselines (pooled and fired-regime), and Louvain vs
  connected components on planted partitions under bridging noise. Run
  and committed (fully synthetic): `layer-ablation.md`.
- `posture_distributions.py`: reads the engine's per-domain behavior as
  distributions: signed marginal entropy change bucketed by observable posture,
  and uncertainty-band width versus evidence. Pure aggregation unit-tested; the
  run is network/maintainer-local (aggregates only).

Reference-anchored / network (maintainer-local, aggregates only):

- `reference_calibration.py`: CAL3/CAL4: the email-policy posterior
  against the authoritative DMARC record, plus the held-out residual
  (the `dmarc_policy` unit masked, so predictor and label are disjoint).
  `--stratify-dir` for per-vertical cells. Memo:
  `reference-calibration.md`.
- `tenancy_reference_calibration.py`: the M365 tenancy posterior (DNS
  channel only) compared with Microsoft's endpoint attestation as corroboration;
  GWS reported one-sided (the channel has no authoritative negative).
- `conformal_coverage.py`: dependent conformal re-split diagnostics on the
  labelable email-policy score. Scorer-development disjointness is not
  established, so the current experiment makes no future-point coverage claim.
  Re-splits of one selected list report singleton, multi-label, and empty-set
  rates separately.

Private-run memo sequence:

```bash
python -m validation.run_calibration_bundle \
  --label "Aggregate Calibration Validation Memo"
```

By default the runner expects:

- `validation/corpus-private/by-vertical/*.txt` for per-stratum reference and
  tenancy calibration.
- `validation/corpus-private/consolidated.txt` for conformal re-split diagnostics.
- `validation/runs-private/<UTC-stamp>/` for `reference.json`, `tenancy.json`,
  `conformal.json`, `memo.md`, and `meta.json`.

Use `--dry-run` to print the exact module invocations without network calls.
If you pass `--stamp`, it must be a single safe path segment: letters, digits,
dots, underscores, and hyphens only. The runner resolves the final run directory
under `--output-root` before writing artifacts. If `--output-root` is inside
this checkout, it must resolve under `validation/runs-private/`; operator-local
paths outside the checkout are allowed.
Before any network harness starts, the runner preflights the private corpus
inputs locally: the consolidated corpus must meet `--min-cell`, at least one
stratum file under `by-vertical/` must meet `--min-cell`, and dry runs print the
eligible and suppressed stratum counts. This catches empty, stale, or
unpublishable corpus layouts before spending operator time on a live run.
Review `memo.md` before copying any result into a committed validation memo.
The renderer is a backstop, not a substitute for review.

### Product-quality live characterization

`characterize_live_quality.py` closes the measurement-tooling gap between the
network-free component benchmark and the private product-quality scorecard. It
runs each private apex sequentially in two isolated configurations, alternating
the CT/no-CT order by row. It measures cold resolver time, primary-source
stages, merge replay, inference, rendering, allocation, event-loop lag,
degradation, warm disk cache, and the actual warm `lookup_tenant` MCP result
envelope. Optional direct Google CSE and BIMI probes remain disabled.

Run the same command with `--preflight` in place of `--execute-network` first.
Preflight validates the source, deterministic selection, row bounds, and path
safety, then prints only counts, digests, method, seed, and the declared network
class. It performs no network calls and creates no directories or files.

```bash
python -m validation.characterize_live_quality \
  --corpus validation/corpus-private/consolidated.txt \
  --output validation/runs-private/<UTC-stamp>/characterization.json \
  --network-class wired \
  --sample-size 50 \
  --sampling-seed stable-v1-characterization-20260812 \
  --normalize-source \
  --exclude-invalid-source \
  --execute-network
```

The input is one lowercase canonical apex per non-comment line. A file already
at or below the default 50-row hard cap runs in its declared order. For a larger
private source, `--sample-size` and a public-safe `--sampling-seed` select rows
by SHA-256 rank without replacement. The aggregate records the source digest,
source eligible count, seed, method, and selected-frame digest, so the sample is
reproducible without publishing its membership. Strict mode rejects duplicate
or non-canonical rows. The explicit `--normalize-source` mode validates and
reduces rows with recon's apex normalizer, removes canonical duplicates, and
records the input, changed, removed, and eligible counts. Malformed rows still
fail the run unless `--exclude-invalid-source` is also explicit. That legacy
preparation mode records the exact excluded count and policy in preflight and
the aggregate. The runner fails instead of silently truncating, uses an empty
config directory per row and mode, and never replaces an existing output.
Exactly one of `--preflight` and `--execute-network` is mandatory, so a copied
command cannot silently start collection.

The JSON output has no field capable of carrying an apex, organization name,
tenant ID, record value, or per-domain row. It contains only the private file's
SHA-256 commitment, counts, quantiles, bounded source/degradation markers,
environment and revision metadata, and the explicit cache and network method.
Keep the first output under `runs-private/`, inspect it, and copy only a reviewed
aggregate memo into a public validation artifact. This runner prepares the
stable-v1 characterization. It does not satisfy the separate preregistered
evaluation-frame declaration or collect an ablation label.

The first reviewed aggregate is
[2026-08-12-stable-v1-live-characterization.md](2026-08-12-stable-v1-live-characterization.md).
It closes the stable-v1 live-characterization prerequisite. The later
[structural-identifiability audit](2026-08-13-quality-arm-identifiability.md)
stopped the frozen private evaluation before target contact.

### Product-quality evaluation frame and structural stop

The stopped decision-bearing study has a separate, immutable frame. Its public
population, source, eligibility window, two-stage sampling rule, cluster rule,
public HMAC contexts, and private key and frame commitments are frozen in
[docs/quality-evaluation-frame-declaration.md](../docs/quality-evaluation-frame-declaration.md).
The source and frame files stay under `corpus-private/`; no evaluation target is
contacted by the preparer. The commands below reproduce the historical frame
preparation only. Do not use the frame for target collection under the voided
design.

```bash
python -m validation.prepare_quality_evaluation_frame generate-key \
  --output validation/corpus-private/v211-sampling-key-20260812.hex

python -m validation.prepare_quality_evaluation_frame prepare \
  --ranked-source validation/corpus-private/tranco-26J79-top1m.csv \
  --exclude-corpus validation/corpus-private/consolidated.txt \
  --output validation/corpus-private/v211-screening-frame-26J79-hmac-v1.csv \
  --sampling-key-file validation/corpus-private/v211-sampling-key-20260812.hex \
  --tranco-list-id 26J79 \
  --expected-source-rows 1000000 \
  --sample-size 2500 \
  --sampling-context v211-screening-frame-20260812-01 \
  --preflight
```

The existing private frame was written once and remains immutable. Do not rerun
write mode against it. Before any target collection code was built or run, the
network-free preflight established that the intended arms collapse and A3 can
never support when A0 abstains:

```bash
python -m validation.quality_arm_identifiability
pytest tests/test_quality_arm_identifiability.py -q
```

The checked-in test exhaustively evaluates all 64 M365 DNS evidence-role
states. It keeps the stop condition blocking if the model, role adapter, score,
or display threshold changes. A future candidate requires a new design and new
commitments after passing this check; it may not reuse the cancelled window.

Committed memos from these network runs must follow
[docs/data-handling-policy.md](../docs/data-handling-policy.md): no apexes, no
organization names, no tenant IDs, no per-domain output, and no small cells.
Report only aggregate counts, rates, intervals, quantiles, and deltas. Suppress
or combine any stratum below 10 domains before committing the memo.

Public paper-number reproduction (no private corpus, no default network):

```bash
python -m validation.reproduce_paper_numbers
```

The default `paper` profile regenerates the public, no-private-data evidence
rows named in `docs/paper-outline.md`: suppression monotonicity, differential
verification, synthetic interval coverage, likelihood sensitivity, and layer
ablations. It writes `summary.md`, `manifest.json`, and per-harness outputs under
`validation/local/paper-numbers/<UTC-stamp>/`, which is gitignored. Use
`--profile smoke` to check the orchestrator quickly without waiting for full
paper-sized sweeps. If you pass `--stamp`, it follows the same single safe
path-segment rule as the calibration bundle runner.

The most recent recorded final public claim audit is the historical
`2026-06-29-scorecard-gate-claim-audit.md`. The most recent recorded local
submission-freeze proof is the historical
`2026-06-30-submission-freeze-local-proof.md`. They record passing checks for
the exact commits named in those memos, not the current tree. Later paper and
package changes leave the current draft unfrozen.
Before external submission packaging, follow
[docs/submission-freeze-checklist.md](../docs/submission-freeze-checklist.md)
to rerun the public proof commands, claim audit, and release gates while
preserving the same private-data and claim-boundary rules.

## The fingerprint catalog audit

Run alongside live validation when changing fingerprint YAMLs:

```bash
python -m validation.audit_fingerprints \
  --markdown-output validation/live_runs/<UTC-stamp>/fingerprint_audit.md
```

The audit is no-network. It reports catalog metadata coverage and classifies
multi-detection fingerprints as `keep_any`, `review_for_all`, or
`tighten_patterns` so match-mode changes stay evidence-driven.

## Policy

Real apex domains never get committed here, not as corpus files and
not as artifacts. Real organization names, tenant identifiers, target-owned
record values, and per-domain notes follow the same rule. `CONTRIBUTING.md`
codifies the same rule for the rest of the repo. The .gitignore carves out
`corpus-private/`,
`runs-private/`, `live_runs/`, and `local/` so users can curate without worrying
about accidentally leaking their list. `scripts/check_validation_hygiene.py`
runs in the local gate and release readiness to catch forced-added private
paths, identity-bearing JSON and NDJSON, target columns in CSV, target-domain
fields, raw target records, tenant and verification identifiers, and detailed
candidate-rejection rows in committed validation artifacts. Generator parity
tests bind the public synthetic sources to every tracked generated artifact.

When you discover a generally-useful pattern (a real third-party SaaS
that any user would benefit from), open a PR adding the
`cname_target` rule to `src/recon_tool/data/fingerprints/surface.yaml`.
Provider names, provider-controlled pattern domains, and public provider
documentation are allowed because they define the generic catalog. The target
that exposed the pattern, its records, and its company details stay private.
