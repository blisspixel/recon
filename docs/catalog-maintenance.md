# Reproducible catalog maintenance

The maintainer workflow has three distinct jobs: select a useful corpus,
collect and measure its bounded public observations, then review candidate
rules. It reuses the existing harnesses rather than adding a crawler, training
system, or automatic promotion service. Runtime collection and claim boundaries
remain unchanged. See [catalog strategy](catalog-strategy.md),
[rule grammar](fingerprints.md), and [data handling](data-handling-policy.md).

## Agent entry points

These skills are source-checkout maintenance instructions, not additional tools
in the public MCP server or changes to the frozen portable plugin evaluation:

| Job | Entry point | Completion artifact |
|---|---|---|
| Select and freeze a corpus | [recon-corpus-plan](../agents/maintainer/skills/recon-corpus-plan/SKILL.md) | Private frame and manifest, aggregate declaration, or explicit missing inputs; no collection |
| Collect or evaluate the frozen round | [recon-catalog-round](../agents/maintainer/skills/recon-catalog-round/SKILL.md) | Private retained observations, typed/stratified aggregates, completeness and decision ledger |
| Refine individual rules | [recon-fingerprint-triage](../agents/claude-code/skills/recon-fingerprint-triage/SKILL.md) | Evidence-backed disposition, scoped rule patch and synthetic regressions |

A harness can load these files directly or install them using its own skill
discovery mechanism. Paths inside them resolve against a recon checkout. They
do not install tooling, start a paid model session, or authorize network work.
An agent may prepare proposals autonomously within the requested task; rule
promotion and publication still require the repository's review and CI gates.

## One round, with explicit boundaries

1. State a question and estimand before selecting rows. Discovery yield,
   classified surface, documented-provider corroboration, and independently
   labeled precision answer different questions. Declare sample limits and
   what the frame cannot represent.
2. Freeze the dated source bytes, selection rule, exclusions, normalized apex
   membership, strata, and implementation/catalog digests. Use keyed rank or
   ccTLD preparers when those designs apply. Equal quotas are discovery budgets,
   not population weights. A ccTLD is a namespace attribute, not geolocation.
3. Separate development from holdout and forward-time drift. The generic round
   preparer deduplicates within the round, but its exclusion-policy text is not
   an exclusion algorithm. Use the actual exclusion files in the specialized
   preparers or a tested comparison before claiming a disjoint holdout. Record
   known duplicated observations or shared templates where independently
   established; apex deduplication alone does not prove independence. Shared
   providers do not establish common organizational ownership.
4. Freeze CT choice, direct probes off, concurrency, failure/retry disposition,
   recurrence thresholds, and the regression budget. Existing historical
   declarations remain immutable. A new question requires a new round, not an
   edited old result. Complete any declared protected-main gate before requests.
5. Collect only when requested. `validation.scan` contacts the supplied corpus;
   planning and reduction of existing results do not. DNS is observable and
   default collection can fetch MTA-STS. Preserve failures, unavailable sources,
   partial collection, truncation, and per-type opportunity denominators. Do
   not replace failed rows with convenient successful rows.
6. Refine candidates on development data. Require exact reusable rule grammar,
   independent provider support or a disclosure-safe basis, a genuine review
   date, synthetic positive/lookalike/sparse fixtures, and exact provenance.
   An independent reviewer can inspect the basis and negatives without seeing
   holdout outcomes. Rule agreement or agent agreement is not ground truth.
7. Freeze the candidate before a one-shot holdout. If evaluation reveals a
   defect, fix it, but do not report the reused holdout as independent proof of
   the revised rule. Declare a new untouched evaluation. Drift comparisons must
   disclose changed observation surfaces and withhold classification comparisons
   across unequal interpretation/catalog commitments.
8. Publish only a disclosure-reviewed aggregate decision and supported generic
   patterns. Per-domain rows, membership, opaque tokens, and keys stay private.
   A hash is an integrity commitment, not anonymization or collector attestation;
   small-cell suppression alone is not a general privacy guarantee.

## Executable path

Run from the checkout root. The strict plan schemas and specialized rank,
ccTLD, provider-seed, and drift examples live in
[validation/README.md](../validation/README.md). Inspect the selected command's
`--help`; do not apply one round's flags or schema to another.

The generic offline preparation step is:

```text
uv run python -m validation.prepare_catalog_round --plan validation/corpus-private/round-plan.json --output-corpus validation/corpus-private/round-frame.txt --output-manifest validation/corpus-private/round-manifest.json
```

Only after the corpus and collection are approved and frozen, use
`uv run python -m validation.scan` with `--corpus`, `--round-kind`, and
`--round-manifest`. Match `--ct` to the plan; the runner defaults to CT off.
Pass the frozen recurrence threshold as `--min-count` and declared parallelism
as `--concurrency`. Independent non-drift rounds use `--no-compare` unless an
exact prior comparison was declared; otherwise scan selects the latest local
run. Drift instead requires its explicit prior and comparison sidecar.
It creates the pooled typed baseline. Existing-result stratification uses
`validation.stratify_catalog_round` with the original `--round-plan`,
`--round-manifest`, `--input`, `--pooled-aggregate`, and private `--output-dir`.
Neither evaluation nor triage silently triggers another collection.
Candidate review alone can use an existing artifact without a full frozen
bundle, while explicitly withholding independent or contract-bound evaluation
claims. Review-only tasks produce findings and proposed patches, not catalog
mutations; unrun local gates and CI are `not checked`, never implicitly passed.

### What the promotion evaluator establishes

`validation.evaluate_catalog_promotions` is deliberately narrower than the
runtime detector. It reclassifies retained unmatched values using built-in
`match_mode: any` DNS-suffix rules in `cname_target`, `mx`, `ns`, and `spf`.
It rejects conjunctions and operator-local candidates. Reports retain the
canonical YAML digest and an additional digest of the exact normalized rules
evaluated. They do not bind a full service-selection counterfactual.

Its additive classified-count arithmetic cannot decrease by construction.
Therefore a zero-regression result does not establish absence of false
attribution, provider displacement, or misleading service claims. `accepted`
means that this diagnostic's frozen bookkeeping conditions passed, not that
every promotion gate passed. Other record types and conjunctions need dedicated
detector tests and a separately supported validation route. Do not convert
`all` to `any` merely to pass the evaluator.

Run focused tests, `uv run python scripts/generate_fingerprint_catalog.py --write`
when catalog source changes, and `uv run python -m validation.audit_fingerprints
--freshness`. Finish with `uv run --frozen python scripts/check.py` and the
hosted CI matrix for the exact proposed revision. Do not lower floors or
regenerate expected outcomes to conceal a regression.

## Research basis and limits

These are design implications for recon, not measured improvements to recon's
accuracy or permission to expand its collection surface:

- Top-list selection and date can materially change Internet measurements.
  Preserve the exact frame and report results for that frame. [A Long Way to
  the Top, IMC 2018](https://arxiv.org/abs/1805.11506).
- Reproducible, manipulation-hardened rankings improve repeatability but do not
  turn equal rank quotas into a representative population sample.
  [Tranco, NDSS 2019](https://arxiv.org/abs/1806.01156).
- Separation across development, evaluation, and time guards against optimistic
  evaluation. This is a methodological analogy from malware classification,
  not a recon accuracy result. [TESSERACT, USENIX Security
  2019](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury).
- Heuristic evidence sources can overlap, conflict, and correlate. Preserve
  their derivation and do not count repeated evidence as independent labels.
  This motivates dependency-aware review, not adopting a learned label model.
  [Snorkel, 2017](https://arxiv.org/abs/1711.10160).
- Abstention should be visible beside coverage and errors on appropriately
  labeled cases. Statistical risk guarantees require a suitable labeled
  sampling setup; recon's confidence tiers do not supply it. [Selective
  Classification, NeurIPS 2017](https://arxiv.org/abs/1705.08500).

Learned weak supervision, retuned priors, and conformal guarantees remain
research proposals until a defined claim, independent labels, a frozen loss,
and defensible sampling/dependence assumptions exist. More matches alone do
not justify them. An unavailable observation, an unsupported pattern, or a
deferred promotion is often the most accurate result.
