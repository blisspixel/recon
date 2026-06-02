# Bayesian-layer validation, full-corpus pass, 2026-06-02

Pre-2.0 full-corpus calibration pass on the private corpus. Aggregate metrics
only; no domain names appear here (the corpus and per-domain output stay
gitignored under `validation/corpus-private/` and `validation/runs-private/`).

This memo follows the Track C-cal legitimacy refinements in `docs/roadmap.md`:
it reports *consistency*, not ground-truth calibration (CAL1), attaches
uncertainty to the headline number (CAL2), and separates coverage from
calibration in the per-node verdict (CAL5). The open refinements (CAL3 interval
coverage, CAL4 ground-truth subset, CAL6 stratified per-stratum reporting) are
listed under Limitations.

## Run

- Source: `recon batch <corpus> --ndjson --fusion --no-ct --include-unclassified`
  at batch concurrency 5.
- Coverage: full corpus. 5,238 successful of 5,241 domains (99.94%); 3 errors.
- Concurrency note: a concurrency-16 pass blew the 120s per-domain budget on
  ~84% of domains through DNS-resolver saturation; concurrency 5 holds the
  error rate at 0.06%. Full-corpus DNS / identity passes run at low batch
  concurrency.
- No-CT: the nine Bayesian nodes are fed by DNS and identity-discovery
  endpoints, not certificate transparency, so a no-CT pass calibrates the layer
  in full. CT feeds only the separate `infrastructure_clusters` and cert lexical
  surfaces, validated separately under their own rate limits.

## What we measure, and what it does and does not show

The deterministic-vs-Bayesian number below is a **consistency** check: both
layers consume the same observed evidence, so agreement shows they do not
contradict each other, not that either is correct. It is **not** calibration
against ground truth, and the per-node Brier / log-score / ECE are computed
against the deterministic pipeline as a **proxy label**. Real calibration and
interval coverage require the ground-truth subset (CAL4) and are not yet
available.

## Consistency (deterministic vs Bayesian, high-confidence posteriors)

- 13,307 of 13,307 high-confidence (posterior >= 0.85, non-sparse) posteriors
  agree with the deterministic pipeline: 100% observed, zero disagreements.
- Rule of Three 95% upper bound on the true disagreement rate: ~3/13,307 ~=
  0.02%.
- Cross-source conflicts: 0 across all 5,238 domains.
- Multi-signal correlation depth (north-star): 3,834/5,238 = 73.2% of domains
  have more than one evidence binding firing across nodes.

## Per-node verdict, coverage separated from calibration (CAL5)

Coverage = how often the node has direct evidence (firings). Calibration = how
well the posterior tracks the proxy label (Brier / ECE) when it does.

| Node | Firings (coverage) | Brier | ECE | Verdict |
|---|---|---|---|---|
| m365_tenant | 3115 | 0.0036 | 0.058 | stable |
| google_workspace_tenant | 1783 | 0.0119 | 0.109 | stable |
| federated_identity | 1232 | 0.0053 | 0.066 | stable |
| okta_idp | 181 | 0.0084 | 0.083 | stable |
| email_gateway_present | 1094 | 0.0084 | 0.091 | stable |
| email_security_modern_provider | 0 (pure propagation) | n/a | n/a | stable |
| email_security_policy_enforcing | 3146 | 0.0480 | 0.188 | stable (weakest) |
| cdn_fronting | 2265 | 0.0010 | 0.031 | stable |
| aws_hosting | 1486 | 0.0052 | 0.062 | stable |

Gates (diagnostic): ECE <= 0.2, Brier <= 0.15, firings >= 10 (coverage).

- All nine nodes are within the calibration gates on the full corpus, and all
  evidence-bearing nodes clear the firing-count coverage gate.
- `okta_idp` is stable on the full corpus (181 firings, Brier 0.0084, ECE
  0.083). Its earlier small-sample "not yet" was a coverage artifact, not a
  miscalibration, as predicted: its Brier / ECE were healthy even at n=12.
- `email_security_policy_enforcing` is the node to watch: highest Brier (0.048)
  and ECE (0.188), still inside the gates but with the least margin.
- Sparse-flag rates are high by design; the passive-observation ceiling is the
  load-bearing fact, not the point estimate.

## Catalog gap report (C2)

`find_gaps` over the run surfaced 1,326 distinct unclassified CNAME-terminal
suffixes. The high-count residual is largely not fingerprintable as third-party
SaaS:

- per-certificate AWS ACM validation CNAMEs (random prefixes),
- big-tech edge / CDN infra (msedge, facebook, google, mozgcp),
- domain parking (hugedomains),
- org-specific infrastructure (vendor-owned `*.cloud` / `*.de` subdomains).

The genuine missing-vendor tail is modest (for example Reblaze WAF, Adobe
Campaign / Neolane, Pega Cloud, Descope, gamania cloudforce). These feed the C1
vendor-doc-sourced fingerprint additions; committed examples will use fictional
brands.

## Limitations (open Track C-cal items)

- **No ground truth yet (CAL3 / CAL4).** Everything above is consistency and
  proxy-label scoring. Real calibration and empirical 80%-interval coverage
  need the hand-labeled ground-truth subset.
- **Whole-corpus, not per-stratum (CAL6).** The full corpus is covered, but the
  numbers are not yet broken out by cloud vendor / vertical / region.
- **Conditional-independence bias (CAL7).** Correlated DNS bindings (for example
  MX + autodiscover + Exchange-DKIM all implying M365) can be double-counted by
  the combination rule, which would narrow intervals. Documented as a known
  limitation pending down-weighting or topology work.
