---
name: recon-corpus-plan
description: Plan a private, reproducible domain corpus for recon catalog development, an independent holdout, or a drift round. Use for maintainer sampling and corpus design, not ordinary domain lookups or live collection.
---

# Corpus planning

This is a repository maintainer skill. It requires a recon source checkout and
its validation harnesses; it is not part of the frozen portable plugin candidate.
Paths below are relative to that checkout, even if this skill is installed elsewhere.

Read `docs/catalog-maintenance.md` and `docs/data-handling-policy.md` first.
Use `validation/README.md` for the selected preparer's exact input contract;
inspect its plan loader and `--help` before producing an executable plan.

## Define the question before selecting rows

Determine whether the user needs candidate discovery, independent evaluation,
or forward-time drift. Record the proposed source, dated revision and digest,
selection rule, sample-size budget, strata, and what the result cannot estimate.
Do not invent a list of organizations or infer corporate ownership from domains.
When only a question is supplied, propose a source and sampling design; a live
download or target lookup is a separate action, not part of an offline plan.

Use the existing preparer that matches the question:

- Rank: `validation.prepare_catalog_rank_frame` for frozen rank bands and
  private keyed sampling, including its actual development-exclusion files.
- ccTLD: `validation.prepare_catalog_region_frame` with frozen IANA and UN M49
  inputs. ccTLD membership is not geography or registrant location.
- Provider relationship: `validation.prepare_vendor_seed_round` with archived
  provider-owned evidence and declared exclusions. A customer label does not
  establish publication of a particular DNS record.
- Drift: `validation.prepare_catalog_drift_round` binds the exact retained
  prior result. Repeating a corpus is not independent evaluation.
- Other declared strata: `validation.prepare_catalog_round` normalizes and
  deduplicates the frame. Its `policies.exclusions` text does not mechanically
  exclude prior development data. Verify that exclusion using a supported
  frame builder or an explicit tested comparison before calling it a holdout.

## Freeze and hand off

Keep source membership, normalized apexes, sampling keys, exclusions, and plans
under `validation/corpus-private/`. Use an exclusive new artifact path, never
replace a previous frame or sampling key to obtain a preferable sample.
Record known observation dependencies without inferring organizational groups.
Freeze CT choice, direct probes off, recurrence thresholds, the proposed
promotion budget, and the development/holdout split before collection.

Run the relevant offline preflight. If required source data, exclusions, or
scope are missing, report the missing input and stop before collection. Output
the private artifact paths, aggregate counts and commitments, readiness or
blocked state, and a proposed collection command. Do not print domain rows.
Planning completes without running that command. An explicitly requested round
can continue using `recon-catalog-round` after the pre-collection gates pass.
