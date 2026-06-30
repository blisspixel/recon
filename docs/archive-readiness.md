# Archive Readiness

Status: pre-submission archive policy and checklist. This file does not add a
DOI, `.zenodo.json`, badge claim, runtime surface, dependency, or network
behavior.

## Sources Checked

- GitHub repository citation and Zenodo release archiving:
  <https://docs.github.com/repositories/archiving-a-github-repository/referencing-and-citing-content>
- GitHub citation files:
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files>
- Zenodo `CITATION.cff` guidance:
  <https://help.zenodo.org/docs/github/describe-software/citation-file/>
- Zenodo software metadata guidance:
  <https://help.zenodo.org/docs/github/describe-software/>
- Zenodo `.zenodo.json` guidance:
  <https://help.zenodo.org/docs/github/describe-software/zenodo-json/>
- ACM artifact review and badging:
  <https://www.acm.org/publications/policies/artifact-review-and-badging-current>
- Security-aware artifact evaluation research:
  <https://arxiv.org/abs/2605.06508>

## Current Policy

Use `CITATION.cff` as the public citation metadata source until a specific
archive path is chosen. GitHub uses that file for citation suggestions, and
Zenodo can use it when archiving a release.

Do not add `.zenodo.json` yet. Zenodo documents that if both `.zenodo.json` and
`CITATION.cff` are present, Zenodo uses `.zenodo.json` and ignores
`CITATION.cff` for GitHub release archiving. That makes `.zenodo.json` a policy
choice, not a harmless metadata addition.

Do not add DOI language yet. A DOI should point at a real archived object for a
frozen artifact, not at an intended future deposit.

## Metadata Decision Discipline

Archive metadata changes are release-policy changes, not documentation polish:

- Keep `CITATION.cff` authoritative until the archive path is chosen.
- Do not add root archive metadata files in preparatory commits.
- Add `.zenodo.json` only in the same reviewed change that records why Zenodo
  needs fields `CITATION.cff` cannot express.
- Do not add a `preferred-citation` block with an arXiv identifier, DOI, or
  venue citation until the paper object exists.
- After a real archive exists, update citation metadata and rerun release
  readiness against the frozen commit.

## Archive Path Decision Packet

Before adding archive metadata or DOI language, write down the decision in the
reviewed change. The packet must contain:

| Field | Required content |
|---|---|
| Frozen object | Exact commit SHA, release tag, and package version being archived. |
| Archive path | Zenodo GitHub integration, venue supplement, or another reviewed repository. |
| Metadata authority | Whether `CITATION.cff` remains sufficient or `.zenodo.json` is needed for Zenodo-specific fields. |
| Zenodo-specific need | If `.zenodo.json` is proposed, name the required field such as `grants`, `communities`, `access_right`, `related_identifiers`, or contributor roles. |
| DOI status | No DOI, pending DOI, or real DOI. Only the real DOI state may be cited in public docs. |
| Paper relation | Whether the archive is standalone software, a venue supplement, or a supplement to a real paper object. |
| Public proof state | Claim audit, public proof profile stamps, local gate, remote readiness, and outside-replication status. |
| Data boundary | Confirmation that no private corpora, real target lists, tenant IDs, per-domain rows, or unsuppressed small strata are included. |

Default to `CITATION.cff` plus the GitHub release unless the archive path needs
metadata that `CITATION.cff` cannot express. Zenodo's current guidance says
`.zenodo.json` overrides `CITATION.cff` for GitHub release archiving and is only
needed for Zenodo-specific metadata such as grants, communities, access rights,
related identifiers, or contributor roles. GitHub's current guidance ties
Zenodo DOIs to public repositories and GitHub releases, so a DOI decision must
name the actual release object rather than a future intended deposit.

## Archive Candidate

The archive candidate is a frozen GitHub release that already has:

- source code for the released package;
- wheel and sdist on PyPI;
- GitHub Release wheel, sdist, SBOM, and attestation export;
- PyPI and GitHub provenance verification through
  `scripts/release_readiness.py --remote`;
- `CITATION.cff` synchronized with version and release date;
- Apache-2.0 license;
- public reviewer commands in [artifact-review.md](artifact-review.md);
- public proof memo in
  [2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md);
- current final claim audit refresh in
  [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md);
- aggregate-safe paper figures in [paper-figures.md](paper-figures.md);
- data-handling policy in [data-handling-policy.md](data-handling-policy.md).

## Freeze Checklist

Before creating or citing an archived artifact:

1. Freeze the paper package against [paper-claim-map.md](paper-claim-map.md).
2. Rerun the public smoke and full paper proof profiles with a new stamp if any
   paper, package, or claim-map wording changed.
3. Run `uv run python scripts/check.py`.
4. Push the frozen commit and verify GitHub CI, Secrets scan, and Scorecard.
5. Run `uv run python scripts/release_readiness.py --remote` on clean `main`.
6. Confirm no private target identifiers or raw private rows are tracked.
7. Choose the archive path: Zenodo GitHub integration, venue supplement, or
   another reviewed repository.
8. Add `.zenodo.json` only if the chosen archive needs Zenodo-specific fields
   that `CITATION.cff` cannot express.
9. Add DOI metadata only after the archive is real and points at the frozen
   artifact.
10. Record one outside public-artifact replication pass when available, using
    aggregate outcome notes only.

## Security Review

Artifact review should not stop at "does it run." The public package should
remain safe to inspect and rerun:

- run the existing static, typing, coverage, validation, text, and release
  gates before freeze;
- keep dependency audit and workflow-pin checks green;
- document that recon is passive, zero-credential, and local by default;
- keep reviewer commands free of destructive actions and credential prompts;
- keep outputs under ignored `logs/` or `validation/local/` paths.

This is a context-aware security review for the artifact, not a new claim that
outside reviewers have validated private-corpus results.

## Stop Rules

- No `.zenodo.json` until an archive policy is chosen.
- No DOI field or badge claim until the archived object exists.
- No public archive that contains private corpora, real target lists,
  organization names, tenant IDs, per-domain findings, or unsuppressed small
  strata.
- No "results validated" wording for private-corpus rows. They remain
  aggregate-only maintainer evidence.
- No new runtime behavior, package dependency, network source, or schema field
  for archive packaging.
