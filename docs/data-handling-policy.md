# Data-handling policy

What may and may not enter this public repository, and how that line is
enforced. [CONTRIBUTING.md](../CONTRIBUTING.md) states the rule for
contributors in short form; this document is the complete policy, mapped
to the mechanisms that keep it, in the style of the
[assurance case](assurance-case.md). It is referenced by the
statistical-assurance work and by any external write-up, where the
constraint shapes how results can be published at all.

The policy follows from the project's invariants
([roadmap](roadmap.md#invariants)), not from caution alone: recon is a
reducer over public observation, it ships no intelligence database, and
it has no reason to accumulate the targets it was pointed at. Keeping
real targets out of the repository removes a standing reputational and
legal liability with no offsetting benefit.

## The one rule

**No real-company data enters the repository, anywhere, ever.** Real
apex domains, organization names, tenant IDs, and per-domain analysis
output must not appear in commits, pull requests, issue or PR comments,
code comments, YAML fingerprints, test fixtures, golden snapshots,
validation memos, or commit messages. "Ever" includes history: a value
committed and later removed still lives in the git history and is
treated as a leak.

## What may enter the repository

| Allowed | Why it is not target data |
|---|---|
| The Microsoft fictional brands (`contoso.com`, `northwindtraders.com`, `fabrikam.com`, `tailspintoys.com`, `wingtiptoys.com`, `adventure-works.com`, `wideworldimporters.com`) and IETF reserved placeholders (`example.com` / `.org` / `.net`) | Fabricated names that teach the method without naming a real target |
| Vendor and product names recon detects (Cloudflare, Okta, Microsoft 365, Google Workspace, Proofpoint, ...) | Detection classes in the fingerprint catalogue, not targeting examples |
| Upstream service hostnames recon itself queries (`login.microsoftonline.com`, `crt.sh`, `api.certspotter.com`, `dns.google`, ...) | Public infrastructure recon talks to, not targets it reports on |
| Aggregate metrics from corpus work (counts, rates, calibration numbers, drift deltas, entropy-reduction distributions) | Statistics over a set, carrying no apex or per-domain identity |
| Synthetic corpora and fixtures (the generator, the fictional-brand sample corpus, the synthetic calibration draws) | Generated data with no real-world target in it |

## Aggregate validation disclosure controls

Aggregate does not mean automatically safe. Following the same risk-based shape
as NIST SP 800-188's de-identification guidance and Census-style disclosure
review, every committed validation memo that came from real apexes must include
or satisfy these controls:

- The input corpus path is private and gitignored (`validation/corpus-private/`
  or another local path), and the per-domain run output stays under
  `validation/runs-private/`, `validation/live_runs/`, or
  `validation/local/`.
- The committed artifact contains no apex domains, subdomains, organization
  names, tenant IDs, per-domain JSON, raw row excerpts, or screenshots.
- Tables report counts, rates, intervals, quantiles, or deltas only. If a
  stratum has fewer than 10 domains, suppress it, combine it with a larger
  bucket, or report only that it was too small to publish.
- Examples inside the memo use the fictional or reserved domains listed above.
  If the real case is load-bearing, describe the behavior generically instead
  of naming the target.
- The memo states which disclosure controls were applied before it is committed.

Research references for this posture:
[NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final) frames
de-identification as a governed release process with risk evaluation, synthetic
data options, and measurable standards. The
[Census FSRDC Disclosure Avoidance Methods Handbook](https://www.census.gov/content/dam/Census/programs-surveys/sipp/methodology/FSRDC%20Disclosure%20Avoidance%20Methods%20Handbook%20v.4.pdf)
is the practical analogue for reviewing statistical outputs before release.

## What may not enter the repository

- Real apex domains or organization names, in any file or message,
  including a "just one example to reproduce" in an issue.
- Per-domain analysis output (a real `recon <domain> --json`, a real
  batch result, a real delta), even if the apex is redacted, because
  the surrounding detail can re-identify it.
- Tenant IDs, region strings, or any identifier tied to a real
  organization.
- Credentials of any kind, including local test keys: API tokens,
  private keys, `.pem` / `.p12` / `.pfx`, `id_rsa` and friends,
  `credentials.json`, `secrets.yaml`. recon needs none to run, so none
  belong here.
- The private validation corpus and its run outputs.

## Where real data lives instead

Real apexes are necessary for accuracy and calibration work, so they
live only in permanently-gitignored paths on the maintainer's machine,
never in a commit:

- `validation/corpus-private/`: the curated real-apex corpus.
- `validation/runs-private/`: per-run outputs (results, gaps, diffs).
- `validation/local/`: any other scratch space.

The committed validation tooling (the runner, gap finder, triage
script, synthetic-corpus generator, the corpus aggregator, the
deterministic harnesses) is allowed because it carries no target data;
it reads the gitignored inputs and emits only aggregate artifacts that
are reviewed before they are committed. See the
[corpus-private structure](../validation/README.md) and the
[maintainer-validation loop](maintainer-validation.md), whose Tier 3 is
the only step that touches the private corpus and which stays local by
construction.

## Policy mapped to mechanism

The rule is enforced by layered mechanisms, not by vigilance alone:

| Mechanism | What it covers | Residual |
|---|---|---|
| `.gitignore` blocks the private paths by default (`/validation/*` is denied, then specific safe tooling is re-allowed by name) | A real corpus or run output cannot be added without overriding the ignore on purpose | An explicit `git add -f` can still force an ignored file in; the reviewer check is the backstop |
| `gitleaks` secrets-scan (`.github/workflows/secrets-scan.yml`) on every PR, every push to main, and weekly over full history | Credentials and key material, including values already in history | Tuned to secret patterns, not to real-apex strings; it catches keys, not company names |
| `scripts/check_validation_hygiene.py`, run by the local gate and release readiness | Forced-added private validation paths, root per-domain JSON dumps, corpus lines, and target-domain fields in committed validation artifacts | It cannot identify every company name in prose or distinguish all vendor reference domains from targets; review still owns that |
| `validation/render_calibration_memo.py`, run after private calibration harnesses emit aggregate JSON | Target-identifying JSON keys, target-looking domain string values, and unsuppressed strata below 10 domains before a memo is rendered | It validates the aggregate payload shape, not the semantic interpretation; a human still reviews the memo before committing |
| The fictional-brand convention (this doc, CONTRIBUTING.md) and reviewer inspection of incoming diffs for real-apex strings | Real company names in examples, fixtures, comments, and prose | Manual; a determined contributor could slip a name past review, which is why the convention is documented loudly |
| The aggregate-only discipline for validation memos and the cohort summary (PV1) | Per-domain identity in committed statistics: only counts, rates, intervals, quantiles, and observability-adjusted prevalence reach the repo | Small-cell suppression and review remain semantic controls, not fully mechanical gates |

The honest position: the deterministic mechanisms (`.gitignore`,
gitleaks) are strong for what they cover, and the rest rests on a
documented convention plus review. The convention is written down
prominently precisely because it is the part a mechanism does not fully
catch.

## Why this also shapes how results get published

Any external write-up about recon inherits this policy: it cannot print
the corpus. That is treated as a feature, not a limitation. Empirical
claims are framed to be reproducible against public oracles anyone can
re-query (DMARC / SPF / MTA-STS records as their own truth, the
Microsoft and Google identity endpoints for tenancy) and against the
fully synthetic calibration harnesses, so a reader can check the method
without the private data. Only aggregate, posture-stratified statistics
and synthetic reproductions are publishable. The same rule that keeps
the repository clean keeps the published results honest about what can
and cannot be shown.

## If real data lands anyway

Treat it as an incident, not an embarrassment to hide. Because history
counts, removing the file in a new commit is not enough: the value must
be scrubbed from history (a history rewrite) and, for any credential,
rotated immediately. The weekly full-history gitleaks run exists so a
leak that survived review still surfaces rather than sitting quietly in
the past.
