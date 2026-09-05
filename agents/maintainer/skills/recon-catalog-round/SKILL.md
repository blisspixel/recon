---
name: recon-catalog-round
description: Run or evaluate a bounded recon catalog-maintenance round from a frozen private corpus and manifest, preserving source availability, holdout separation, and promotion evidence. Use for maintainer collection and validation, not ordinary lookup or automatic catalog expansion.
---

# Catalog round

Requires a recon source checkout. Paths below refer to its root. This maintainer
skill is separate from the frozen portable plugin candidate.
Read `docs/catalog-maintenance.md` and `docs/data-handling-policy.md`, then the
selected round protocol in `validation/README.md`.

## Admit the round

First distinguish review of existing artifacts from a new formal round.
Candidate review can proceed without a full frozen bundle, but must disclose
missing provenance and cannot claim independent or contract-bound evaluation.
Establish whether the rows are development or holdout before mining candidates.
A review-only request permits findings and proposed patches, not catalog edits
or publication. Do not collect missing evidence without a collection request.

For a new formal round, use the supplied private plan, corpus, and manifest. If
missing, return to corpus planning; do not silently construct a convenience
sample. Confirm the user requested collection. Report
the frozen count, CT setting, concurrency, destination of private outputs, and
that DNS and default MTA-STS requests can be visible before collection begins.
Respect any predeclared protected-main or publication gate in the round contract.

Run `--help` rather than inventing preflight flags: rank preparation has an
explicit preflight; generic preparation and scan validate inputs internally.
Collection
uses `validation.scan`, not a shell loop interpolating domain strings. Its
`--ct` choice must match the manifest; direct probes remain off. Do not bypass
manifest or implementation-digest failures, append new rows, silently retry a
holdout, or increase concurrency to finish faster. A failed or incomplete round
remains incomplete; keep the original artifacts and declare any permitted rerun.
For an existing-result task, do not invoke collection at all.
Pass the frozen `--min-count` and `--concurrency` explicitly. For a new
independent non-drift round, use `--no-compare` unless an exact prior was
declared; the scan otherwise chooses the latest local run. Drift requires its
explicit prior and sidecar and must not disable comparison.

## Evaluate observations, then candidates

Use `validation.catalog_baseline` and `validation.stratify_catalog_round` to
retain typed opportunity, availability, failure, partial, and truncation counts.
The lookup field is `dns_catalog_summary`. Empty or unavailable is not a
negative label. An empty queue does not mean complete coverage.

Candidate generation and refinement use development rows only. Hand candidates
to the existing `agents/claude-code/skills/recon-fingerprint-triage/SKILL.md`
promotion gates. An independent reviewer can check exact provider documentation
and synthetic negatives without seeing holdout results. Never let a consensus
of agents or multiple correlated record paths stand in for independent labels.

`validation.evaluate_catalog_promotions` handles only built-in `match_mode: any`
DNS-suffix candidates in `cname_target`, `mx`, `ns`, and `spf`. Its additive
classified-surface result is not complete detector replay, precision, or proof
of no false attribution. A positive budget decision is necessary only for that
diagnostic; it never automatically promotes YAML. Do not loosen a conjunction
or record grammar to make the evaluator accept it.

Freeze candidate rules before an untouched holdout. After inspecting a holdout,
do not tune on it or rename it development and claim the same evaluation is
independent. A follow-up needs a new declaration and disjoint evaluation data.
Keep vendor corroboration, coverage, and independently labeled precision separate.

## Completion

Return a gate ledger: collection completeness, observation-contract parity,
candidate basis, synthetic positive/lookalike/sparse tests, provenance, frozen
budget, holdout status, freshness, full local gate, and hosted CI status.
For review-only tasks, distinguish `not applicable` and `not checked` from pass.
Use pending, promoted, rejected, or deferred with reasons. Keep all real-target
rows and sampling keys private; review even aggregate outputs for small cells
and linkage before publication. No new network result or fingerprint count is
required for a successful round. Deferring unsupported candidates is a valid result.
