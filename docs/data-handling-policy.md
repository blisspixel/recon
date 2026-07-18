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

**No evaluated-target data enters the public repository.** Real apex domains,
organization names, tenant IDs, target-owned records, and per-domain analysis
output must not appear in commits, pull requests, issue or PR comments, code
comments, YAML fingerprints, test fixtures, golden snapshots, validation
memos, or commit messages. History and published source distributions are
inside this boundary: deleting a value from the current tree does not make a
past disclosure disappear.

This boundary applies to evaluated targets, not to the public provider catalog.
Real vendor and product names, provider-controlled service domains used as
generic detection patterns, and their public documentation are expected in the
repository. A provider case study may justify a rule privately, but the named
customer and its observed records do not become a public example.

## What may enter the repository

| Allowed | Why it is not target data |
|---|---|
| Explicit synthetic identities under `.invalid` or `.test`, plus IETF reserved examples (`example.com` / `.org` / `.net`) | Reserved names teach the method without implying an organization or evaluated target |
| Vendor and product names recon detects (Cloudflare, Okta, Microsoft 365, Google Workspace, Proofpoint, ...) | Detection classes in the fingerprint catalogue, not targeting examples |
| Upstream service hostnames recon itself queries (`login.microsoftonline.com`, `crt.sh`, `api.certspotter.com`, `dns.google`, ...) | Public infrastructure recon talks to, not targets it reports on |
| Aggregate metrics from corpus work (counts, rates, calibration numbers, drift deltas, entropy-reduction distributions) | Statistics over a set, carrying no apex or per-domain identity |
| Synthetic corpora and fixtures (constrained reserved scenarios and synthetic calibration draws) | Generated data with no real-world target in it |

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
- Examples inside the memo use only the reserved domains listed above.
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

## Private non-security reports

Public GitHub issues, issue attachments, pull requests, and discussion comments
are inside the repository disclosure boundary. The public issue forms require a
privacy acknowledgement and ask only for reserved synthetic fixtures, sanitized
diagnostics, generic provider patterns, and provider-controlled references.

If a non-security bug cannot be reproduced without a real target identity, do
not open a public issue and do not attach the output to a draft issue. Email the
address in [SECURITY.md](../SECURITY.md) with the subject `Private recon data
report`. Put no target identity in the subject. Share the minimum description
needed first and wait before sending full output. Security vulnerabilities use
GitHub private vulnerability reporting or the security-reporting instructions
instead.

Private correspondence does not become a public reproduction. Any resulting
fix must use a reserved synthetic regression fixture, a generic
provider-controlled pattern, or a disclosure-safe aggregate result before it
enters GitHub.

## Where real data lives instead

Real apexes are necessary for accuracy and calibration work, so they
live only in permanently-gitignored paths on the maintainer's machine,
never in a commit:

- `validation/corpus-private/`: the curated real-apex corpus.
- `validation/runs-private/`: per-run outputs (results, gaps, diffs).
- `validation/local/`: any other scratch space.

Private per-run rows are retained only while they are needed to reproduce and
review the active aggregate memo. Each new private run records its manual local
retention disposition in an ignored `RETENTION.md` inside the run directory, as
defined by [maintainer-validation.md](maintainer-validation.md). Superseded rows
are removed when that disposition says they are no longer needed. The curated
input corpus can remain local for longitudinal validation, but neither the
corpus nor per-run rows may be committed, published, or copied into an agent
transcript.

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
| `scripts/check_validation_hygiene.py`, run by the local gate and release readiness | Forced-added private paths, tracked and nonignored untracked candidates, unsafe filenames, structured identity fields, Python literals, detailed rejection rows, and non-synthetic identifiers in public validation artifacts | Provider references are explicitly separated from evaluated targets; organization-shaped free prose still requires review |
| Private validation output-root guards in `validation/run_path_safety.py` and the agentic UX harness | Maintainer-local runners reject in-repository output roots outside ignored validation workspaces before collection or provider initialization | Outside-repository operator paths are allowed; review still owns anything copied back into the repo |
| `validation/render_calibration_memo.py`, run after private calibration harnesses emit aggregate JSON | Target-identifying JSON keys, target-looking domain string values, and unsuppressed strata below 10 domains before a memo is rendered | It validates the aggregate payload shape, not the semantic interpretation; a human still reviews the memo before committing |
| The reserved-synthetic convention (this doc, CONTRIBUTING.md) and reviewer inspection of incoming diffs for evaluated-target identities, records, and output | Real target names and values in examples, fixtures, comments, and prose | Manual; a determined contributor could slip a value past review, which is why the convention is documented loudly |
| The aggregate-only discipline for validation memos and the cohort summary (PV1) | Per-domain identity in committed statistics: only counts, public-claim rates, model support coverage, intervals, and quantiles reach the repo | Small-cell suppression and review remain semantic controls, not fully mechanical gates |

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

Public-list checks may serve as robustness checks across re-queryable lists, but
they are not population rates, benchmark prevalence, or a substitute for a
reviewed public release model. A frozen real-apex label snapshot remains
deferred under
[public-label-snapshot-decision.md](public-label-snapshot-decision.md) unless a
separate data-handling and architecture review approves it.

## Historical published-artifact exception

A 2026-07-18 full-history and distribution audit found a bounded set of
pre-policy artifacts. A retired 38-row apex-only input list persisted in four
older source distributions; it contained no credentials, tenant IDs, or
per-domain results. Git history, release source snapshots, and the sealed
v2.6.3 source distribution also retain a detailed per-domain agentic record,
two former agentic fixtures, a rendered snapshot, and a candidate memo whose
rejected rows were not aggregate-only. Those artifacts can contain opaque
identifier-shaped or token-shaped values and domain occurrences. None of the
identities or values are repeated here.

The audited artifacts are absent from the current tree, and the strengthened
gate prevents their current shapes from returning. That does not remove them
from existing Git objects, already downloaded distributions, mirrors, caches,
or release source snapshots. PyPI distribution bytes are immutable in place;
GitHub release assets can be removed or replaced, but doing so cannot retract
copies. Existing attestations remain valid evidence for their original
artifacts and commits. Rewriting tags and branches would sever the same-name
source and provenance alignment without erasing those copies.

The project therefore records the complete audited exception instead of
presenting a partial reference rewrite as erasure. It does not authorize new
target data. The project maintainer owns any retraction decision and must
reassess it after a legal, safety, or credential report, or after a material
change in hosting or package-index removal capabilities. Such a response must
be coordinated across GitHub, package indexes, mirrors, signatures, caches,
and downstream users.

## If real data lands anyway

Treat it as an incident, not an embarrassment to hide. Stop publication,
remove the data from the current tree and open changes, assess every published
channel that received it, and document a coordinated remediation decision.
History rewriting is one possible control, not proof of retraction once signed
or immutable artifacts have propagated. Rotate any credential immediately.
The weekly full-history gitleaks run exists so a leak that survived review still
surfaces rather than sitting quietly in the past.
