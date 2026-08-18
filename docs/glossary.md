# Glossary

recon's load-bearing terms, defined once. Every other document links here rather
than redefining, so a term means one thing across the whole doc set. Where two
surfaces once used one word for two things, the split is named below.

## Output and claims

**briefing.** The default view: the fixed rows recon shows without flags, plus
the cuts it applies to long lists (the high-signal related-domain selection, the
insight cap, the withheld-count notes). Named in code (`formatter/briefing.py`)
and in [ADR-0016](adr/0016-plain-emits-the-panel-record.md) and
[ADR-0017](adr/0017-one-briefing-in-every-shape.md). The panel, `--plain`,
`--md`, and the MCP text surface all render the same briefing; each surface's
`--full` restores the complete record.

**confidence** (panel `Confidence`, JSON `confidence`). A deterministic merged
tier, `high | medium | low`, over source count, same-claim corroboration, and
source degradation: a degraded source lowers it. It is not a raw source count
and not a probability, and it is not confidence in every row. Canonical
definition: [schema.md](schema.md). Distinct from `evidence_confidence` and
`inference_confidence` below, which share the name stem but answer different
questions.

**evidence_confidence.** Count-based confidence from distinct, error-free sources
that contributed useful data. One of the three JSON confidence fields.

**inference_confidence.** The strength of the strongest error-free, same-claim
corroboration chain; unrelated claims do not combine. One of the three JSON
confidence fields.

**model support** (panel row). A threshold-relative display of a claim's
hand-set uncertainty band against the model's decision threshold. It answers a
different question from `Confidence`: `Confidence` counts corroborating sources,
`model support` is where the band sits relative to a threshold, so a one-source
record can carry a full model display. The panel says so on the row when the two
scales sit two steps apart. Not to be confused with the cohort estimand
"model-support coverage" in [aggregate-state.md](aggregate-state.md), which is a
fraction over a domain set.

**evidence role.** The record shape that established a label: an MX delivery path
versus an administrative TXT token, an identity endpoint versus a verification
record. The default view compacts the role qualifier out of service and provider
labels and `--explain` / `--verbose` / `--full` restore it
([ADR-0012](adr/0012-default-view-evidence-role-visibility.md)). One exception:
`provider:` on a role split keeps its role, because there it repeats a vendor
word the reader has already heard and the role is what makes the repeat a second
fact.

**slug.** The identifier for one observed public-record pattern, for example
`microsoft365` or `dmarc`. A slug is what a fingerprint detection carries; the
catalog may hold more than one detection record that resolves to the same slug.
A slug match means the evidence fits a pattern, never that a product is in use.

**claim family.** The audit unit in
[default-claim-audit.md](default-claim-audit.md): a group of claims sharing a
generation path and lineage obligation. Distinct from a provider family (a group
of related vendors), a source family (a group of collectors), and a question
family (a kind of lookup); when a document writes bare "family," the surrounding
noun says which.

**observation opportunity.** The collection-axis state of one channel:
`not attempted`, `observed value`, `observed empty`, `unavailable`,
`not enabled`, or `not applicable`. It models whether recon got to look, kept
separate from whether a claim is supported. The `assess_exposure` component
`state` enum in [mcp.md](mcp.md) is a separate, exposure-component axis, not this
one.

**degraded source.** A source that failed or returned partial data. It is
surfaced in `degraded_sources` on every surface, but it does not always flip the
top-level `partial` flag: CT-provider degradation (crt.sh, CertSpotter) is
chronically flaky and is handled by fallback and cache, so it does not flip
`partial`, while a core-channel failure (DNS, OIDC, identity) does.

**lineage_status.** Two disjoint enums share this name, one per document, and
they are different fields. The runtime terminal-node enum in [schema.md](schema.md)
is `exact | exact_rule_only | reconstructed | unsupported`. The audit-record enum
in [default-claim-audit.md](default-claim-audit.md) is `exact | incomplete |
static`. A reader meeting one should not assume the other.

## Artifacts and evaluation

**capsule.** A caller-owned, replayable observation artifact: retained raw
observations, normalized facts, per-source opportunity states, an evaluation
`as_of`, and version and catalog digests, produced by `recon capsule capture`.
It is caller-owned and local; recon operates no store.
[ADR-0014](adr/0014-caller-owned-capsules-and-okf-deferral.md),
[observation-capsules.md](observation-capsules.md).

**vantage.** Two senses, kept distinct. The physical observation point (which
resolver, from where) that shapes what public DNS returns; and the
caller-supplied `--vantage` label string on a capsule, which is an unvalidated
annotation, not a measurement. A capsule's `--vantage` records what the caller
says the vantage was, and recon does not verify it.

**arm (A0 to A3).** The four arms of the quality-ablation evaluation that was
stopped before target collection: the deterministic baseline and the Bayesian
candidate under two role adapters. Their exact definitions live in the
[preregistration](quality-baseline-preregistration.md) and
[docs/roadmap.md](roadmap.md); [correlation.md](correlation.md) numbers the same
four 1 to 4. The ablation was stopped because the arms collapse (A1 equals A0,
A2 equals A3) so its promotion gate is structurally unreachable.
