<!--
Default pull-request template. Fingerprint-only PRs can switch to the
fingerprint template by appending ?template=fingerprint.md to the PR
URL; see .github/PULL_REQUEST_TEMPLATE/fingerprint.md.
-->

## Summary

<!-- 1-3 sentences: what changed and why. -->

## Test plan

<!-- Bulleted markdown checklist of how to verify the change. -->

## Discipline checks

- [ ] **CPT-change discipline (v1.9.6+).** If this PR changes any
      CPT entry, prior, or likelihood in
      `recon_tool/data/bayesian_network.yaml`, the YAML carries a
      comment explaining the *concept* this change reflects (not
      just the corpus statistic that motivated it). See
      [`CONTRIBUTING.md`](../CONTRIBUTING.md#cpt-change-discipline-v196)
      for the worked examples, anti-pattern catalog, and the
      concept-comment rubric. Reviewers: a "lowered P(X|Y) from 0.75
      to 0.55 to match corpus" change without a concept comment is
      the canonical rejection.
- [ ] **Fingerprint discipline.** New or modified fingerprints carry
      `description` text; the `validate_fingerprint.py` script
      passes locally. (Skip if no fingerprint YAML touched.)
- [ ] **No real-company data.** Committed examples and tests use
      Microsoft fictional brands (Contoso, Northwind, Fabrikam) or
      anonymized aggregates. Private corpus stays under
      `validation/runs-private/` and `validation/corpus-private/`.
- [ ] **No `Co-Authored-By: Claude` trailers** in commit messages
      unless explicitly requested for this work.
