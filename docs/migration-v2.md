# Migrating to recon v2.0

> **Status: final for v2.0.** Every section is populated; this is the
> migration guide that ships with the 2.0 release.

## What v2.0 means for you

recon v2.0 is a schema lock and documentation snapshot, not a
feature release. Everything new since v1.9.0 has already shipped
as a v1.9.x patch under an EXPERIMENTAL label; v2.0 promotes the
fields that proved out and removes the label. No new behaviour
ships in v2.0 itself.

If you have been pinning to a v1.9.x version, the v2.0 upgrade
should be a no-op in code. The only behavioural difference is
that v2.0's CLI, JSON output, and MCP tool descriptions no
longer carry the "experimental" qualifier on the fields listed
below.

## Field promotions

The following EXPERIMENTAL fields are promoted to stable in v2.0.
Most keep their shape; the two exceptions, noted below, were
reshaped during the pre-lock schema-hardening pass (SH2, SH5) so
they would not need a breaking change after the freeze.

| Field | First shipped | v2.0 status |
|---|---|---|
| `posterior_observations` | v1.9.0 | Stable. Shape pinned: `name`, `description`, `posterior`, `interval_low`, `interval_high`, `evidence_used`, `n_eff`, `sparse`, `conflict_provenance`. |
| `slug_confidences` | v1.9.0 | Stable. Reshaped in v2.0 (SH2) from a `[slug, posterior]` pair array to an object map `{slug: posterior}`, parallel to `detection_scores`. |
| `chain_motifs` | v1.7.0 | Stable. |
| `wildcard_sibling_clusters` | v1.7.0 | Stable. Reshaped in v2.0 (SH5) from a list of string lists to a list of `{names: [...]}` objects. |
| `deployment_bursts` | v1.7.0 | Stable. |
| `infrastructure_clusters` | v1.8.0 | Stable. |
| `ecosystem_hyperedges` | v1.8.0 | Stable. Batch-only contract, present only when `--include-ecosystem` is set on `recon batch`. |
| `evidence_conflicts` | v1.7.0 | Stable. |
| `--fusion` CLI flag | v1.9.0 | EXPERIMENTAL label dropped. |
| `--explain-dag` CLI flag | v1.9.0 | EXPERIMENTAL label dropped. |
| MCP `get_posteriors` tool | v1.9.0 | EXPERIMENTAL label dropped. |
| MCP `explain_dag` tool | v1.9.0 | EXPERIMENTAL label dropped. |

New top-level fields added by the schema-hardening pass, stable from
v2.0: `fusion_enabled` (bool, whether the Bayesian layer ran),
`record_type` (output-mode discriminator), `schema_version`, and on
the batch error record `error_kind` (enum: validation, lookup,
timeout). These are additive, so a v1.9.x consumer that ignores
unknown fields is unaffected.

## Bayesian-network node disposition

The v1.9.5 per-node stability validation classified each node
in `bayesian_network.yaml` as `stable` or `not yet`. v2.0 ships
only the nodes that cleared all three criteria
(evidence-response, calibration, independent-firing count).

The one `not yet` node after v1.9.6, `okta_idp`, ships in v2.0 with a
keep-with-caveat disposition: it cleared the evidence-response and
calibration criteria, and its independent-firing count is recorded in
the YAML as a corpus-exposure caveat rather than a blocker. All nine
nodes ship.

## Schema version bump

`docs/recon-schema.json` bumps to v2.0 at tag time. The
`$id` field changes to reflect the new version. Consumers that
pin to a specific schema version should update the pin; the
field set is a superset of v1.x's stable set (every v1.x stable
field stays present), so the only consumer-visible change is the
absence of "experimental" in field descriptions.

The CI gate
(`tests/test_json_schema_file.py`,
`tests/test_schema_disposition.py`) verifies the v2.0 schema
matches the disposition table exactly.

## What v2.0 does NOT change

- **Wire format.** Every v1.9.x JSON output remains parseable by
  a v2.0 consumer.
- **CLI commands.** Same subcommands, same arguments, same exit
  codes.
- **MCP tool names.** Identical to v1.9.x.
- **Default panel layout.** Same blocks, same field labels. Any
  v1.9.x panel-text invariant (humble tone, no overclaim) is
  preserved.
- **`bayesian_network.yaml` topology.** Locked at v2.0; further
  changes require a schema-version bump.

## Downgrade path

If you upgrade to v2.0 and need to roll back to v1.9.x for any
reason:

```
pip install --upgrade "recon-tool==1.9.10.1"
```

Caches written by v1.9.x continue to load under v1.9.x; v2.0
caches load under v1.9.x as well (the v1.9.x cache reader
ignores unknown fields, which has been the contract since
v1.9.3.1). No data-migration step is needed in either direction.

## What stays in the post-v2.0 backlog

The roadmap's [Backlog (after v2.0)](roadmap.md#backlog-after-v20)
lists feature candidates that did not claim slots in the v1.9.x →
v2.0 path. Any of them may ship in a v2.x.y patch when there's a
falsifiable defensive case and corpus evidence to back it. v2.0
itself does not commit to any of them.

## How to verify your v2.0 install

```
recon --version          # prints 2.0.0
recon doctor             # first line should read "v2.0 stable schema"
```

`recon doctor`'s "v2.0 stable schema" line confirms the locked
schema is present in the installed wheel.

## Questions

- File issues at https://github.com/blisspixel/recon/issues
- Security reports per `SECURITY.md`.
