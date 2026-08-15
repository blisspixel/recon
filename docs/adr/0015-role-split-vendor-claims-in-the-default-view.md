# ADR-0015: Role-split vendor claims in the default view

- **Status:** Accepted
- **Date:** 2026-08-15

## Context

A domain can publish a mail vendor and an identity vendor that are not the same
company. recon observes both, retains evidence for both, and scores both above
threshold. The default panel then names one of them.

An independent black-box play-test of the published 2.14.1 package reproduced
this 3/3 on an authorized target. The panel read:

```
  Provider     Google Workspace
  Tenant       c7c08208-4f4d-45f1-83cd-5e2f491ab786 • NA
  Auth         Federated
  Confidence   ●●● High (3 sources)

Services
  Email        Google Workspace, DMARC reject, DKIM
```

while the same run's JSON carried `microsoft365` in `slugs` and in `services`,
`detection_scores` `medium` for both vendors, `slug_confidences` of ~0.95 and
~0.96, and posteriors of ~0.90 for `google_workspace_tenant` and ~0.95 for
`m365_tenant`. Every field was individually correct.

Three mechanisms combine to hide the second vendor:

1. `provider_line` summarizes **MX delivery paths**. The vendor with no MX
   evidence cannot appear, so the row names the mail vendor and reads as though
   it named *the* vendor. The label `Provider` carries no role word.
2. `CATEGORY_BY_SLUG` files both `microsoft365` and `google-workspace` under
   `Email`. The identity-observed vendor is therefore categorized as a mail
   service, and the detailed view renders it `Microsoft 365 (role unavailable)`
   (accurate, because it has no *mail* role), but its identity role is never
   surfaced. ADR-0012 then omits `(role unavailable)` labels from the default
   view, which is correct on its own terms and removes the last trace.
3. `Model support` reports the single weakest claimed node, so it names one of
   two above-threshold tenant-class posteriors.

The `Tenant` row does show the Microsoft tenant GUID, but a GUID carries no
vendor word, so it does not correct the headline.

The prior position was that `docs/schema.md` should document the split. The
play-test evidence retired that position: the note describes the *identity-only*
case, where a vendor is absent from `slugs`, and the observed case is not that.
`microsoft365` is present in `slugs` and `services` and the panel still withholds
it. A schema document also does not reach a reader before they read the panel.

The claim-discipline invariant in `ROADMAP.md` and the default-view policy in
[ADR-0012](0012-default-view-evidence-role-visibility.md) make this a decision
record rather than a rendering tweak.

## Decision

When two or more vendor claims are above threshold in **different evidence
roles**, the default view names each one with its role instead of choosing one.

- The single `Provider` row becomes role-labelled rows (`Mail` and `Identity`)
  **only** when a role split is actually observed. A domain whose vendors agree,
  or which publishes only one vendor claim, renders exactly as it does today
  under the existing `Provider` label. This is an additive branch, not a
  reshaping of every panel.
- The identity-role claim is derived from **evidence provenance**, not from slug
  category: a vendor qualifies when it carries evidence from an identity
  endpoint (`OIDC Discovery`, `GetUserRealm`, `Autodiscover`, or
  `Google Identity Routing`). Deriving it from `CATEGORY_BY_SLUG` would be
  wrong, because that table's category is a catalog property of the slug, not a
  statement about what was observed on this domain.
- `Services` gains an `Identity` row carrying the identity-role vendor, so the
  category block stops filing an identity observation under `Email` with no
  mail role.
- `Model support` names **every** above-threshold tenant-class claim rather than
  only the weakest one, so it cannot corroborate one vendor while a second sits
  equally supported.

### What this does not change

- No claim is upgraded. Both rows already exist as retained evidence; this
  changes which of them the compact view is willing to print, never how much
  they assert. A role that recon cannot establish stays absent under ADR-0012.
- Every machine surface is untouched: `--json`, `--csv`, the MCP payloads, the
  cache, and the capsule schema keep their current fields and semantics. The
  `provider` JSON field keeps its MX-delivery-path meaning exactly.
- `slugs` keeps its documented meaning: fingerprint-catalog pattern matches. The
  question of whether identity-only vendors should enter `slugs` is **not**
  settled here and remains open for the v3 claim-envelope boundary.
- Absence stays absence. A domain with no identity evidence gets no `Identity`
  row, not an empty one.

## Consequences

A reader who stops at the compact panel can no longer form a single wrong
primary vendor, which was the reported failure: the first sentence written into
a ticket or a vendor review said "they run Google" about a domain with a
federated Microsoft tenant.

The panel grows one row on split records. That is the intended cost, and it is
paid only where the ambiguity exists.

`Provider` remains the label for the unsplit case, so the common single-vendor
panel keeps a stable shape and existing screenshots and docs stay accurate.

Insight wording is unchanged. `Federated identity observed; external IdP not
identified` remains correct on a split record: GetUserRealm `Federated` means
the Microsoft tenant delegates authentication to an external IdP, and the tenant
GUID identifies the relying party rather than the IdP it federates to. The
play-test read that line as false; it is true, and it read as contradictory only
because the panel gave the tenant no vendor word. This ADR removes that cause.

## Alternatives considered

**Keep one row and add role words in parentheses.** Smaller diff, and it fixes
the headline. Rejected because it leaves `Services` filing the identity vendor
under `Email` and leaves `Model support` naming one of two claims, so two of the
three mechanisms survive.

**Refuse a headline when two tenant-class claims are both above threshold.**
Rejected. Both claims are true and operationally useful, and suppressing the row
discards the MX fact an operator needs. The play-test argued the same.

**Document only.** This was the prior position. Retired by the evidence above.
