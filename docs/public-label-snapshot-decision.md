# Public Label Snapshot Decision

Status: active publication decision. This document does not add runtime
behavior, validation data, or a new release artifact.

## Decision

Do not publish a frozen real-apex or organization identifier list under the
current data-handling policy.

The external write-up can describe the capture method, aggregate calibration
results, public proof harnesses, and synthetic reproduction bundle. It must not
commit or archive a list of real target domains, organization names, tenant IDs,
or per-domain labels.

## Why

The repository invariant is direct: [data-handling-policy.md](data-handling-policy.md)
says real-company data never enters the public repository, and
[roadmap.md](roadmap.md#invariants) says public artifacts never contain real
apexes, organization names, tenant IDs, per-domain findings, or unsuppressed
small strata.

Current public guidance supports the same release posture. NIST SP 800-188
frames de-identification as a release-model decision that needs explicit risk
evaluation and governance before publishing data about individuals or
establishments. The NIST Privacy Framework 1.1 draft keeps privacy as ongoing
risk management, not a one-time masking step. For recon, a real-apex label
snapshot is an establishment-level target list with linkability risk, so
aggregate-only release remains the default until architecture review approves a
different model.

A hash-pinned public label snapshot would still be a real target list. Hashing
the file, recording a capture date, or placing it in an archive would improve
external result reproducibility, but it would also create a durable corpus of
organizations the project measured. That changes the risk model and conflicts
with the current invariant.

DNS, certificate-transparency, and identity-endpoint observations also drift.
A frozen label list would prove one historical run, not current ground truth.
That is useful for a benchmark, but it is a different publication model from
recon's current aggregate-only validation posture.

## What Stays Publishable

- Public commands that exercise the method without private corpora.
- Synthetic harness outputs and public proof harnesses.
- Aggregate calibration metrics after disclosure review.
- Small-cell-suppressed strata and distribution summaries.
- A capture protocol that lets another reviewer run their own local list.

## What Would Change This Decision

Publishing a real-domain label snapshot requires an explicit data-handling and
architecture review before any artifact is created. That review would need to
approve the release model, target-list governance, disclosure controls, update
policy, and takedown process. Until then, the snapshot remains deferred.

## Paper Wording

Allowed wording:

> The public artifact reproduces the method and synthetic or public proof rows.
> Private-corpus aggregate rows are maintainer-reproducible only because the
> project does not publish real target lists.

Disallowed wording:

> A frozen public label snapshot will be released with the submission.

The second statement conflicts with the current policy and should not appear in
the paper package.

## References

- [NIST SP 800-188, De-Identifying Government Datasets](https://csrc.nist.gov/pubs/sp/800/188/final)
- [NIST Privacy Framework 1.1 Initial Public Draft](https://csrc.nist.gov/pubs/cswp/40/nist-privacy-framework-11/ipd)
