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
| The fictional-brand convention (this doc, CONTRIBUTING.md) and reviewer inspection of incoming diffs for real-apex strings | Real company names in examples, fixtures, comments, and prose | Manual; a determined contributor could slip a name past review, which is why the convention is documented loudly |
| The aggregate-only discipline for validation memos and the cohort summary (PV1) | Per-domain identity in committed statistics: only counts, rates, and observability-adjusted prevalence reach the repo | The discipline is a review rule, not a gate; the committed artifacts are small and human-checkable |

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
