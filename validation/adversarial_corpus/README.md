# Adversarial DNS-record corpus

A hand-authored corpus that measures how the shipped inference engine behaves when
a passive observer is fed DNS records an operator can publish for free. It runs
end to end, records first, fully offline, and converts the correlation.md section
4.11 commitment on Pattern I (planted administrative tokens) into a dated,
falsifiable result.

## What it is, and is not

This is Level 2 evidence on the statistical-assurance ladder: synthetic worlds
sampled from the same model. It uses no real targets, so it licenses no accuracy
rate, recall, precision, or prevalence claim. Every fixture is a reserved-namespace
record set, so "no real company data" is structural, not a promise. What the round
answers is narrow and worth having: on a named, designed-in defect vector, does the
engine move a supported decision on evidence an adversary can publish without
routing any traffic, and by how much.

## The layer, and why records not `infer()`

Fixtures are raw apex DNS record sets: lists of `(record_type, value)` strings over
TXT, MX, NS, and CNAME (SPF and DMARC are TXT values). They feed
`replay_cached_dns_fingerprints` (`recon_tool.sources.dns_replay`), the shipped
matcher path, then `merge_results`, then `infer_from_tenant_info`. The last call
applies the record-role gate in `bayesian_observations.signals_from_tenant_info`
before inference, so the round measures the engine including its provenance gate.
An abstract `infer()` harness feeds observation nodes directly and skips exactly
that gate, which would report a flip the real pipeline prevents.

The record-role gate is the object under test. `m365_tenant_observed` (and the
parallel Google, gateway, CDN, and AWS observations) fire only from evidence whose
record type carries the claimed role (HTTP, MX, DKIM, CNAME, SRV, or a role-typed
CNAME), so a generic verification TXT that produces a vendor slug does not satisfy
them. The round asks whether that gate is complete against every administrative
record a passive adversary can plant.

## Fixture classes

- **gate_path**: the four identity scalars (`tenant_id`, `auth_type`,
  `google_auth_type`, `google_idp_name`) are held `None`, so the only route to a
  gated node is the record-role evidence gate. The runner asserts this before
  scoring; a stray scalar is a fixture bug, raised, not a recorded flip.
- **bypass_path**: a named scalar is injected to probe an ungated route
  (`federated_sso_hub` on `auth_type`, `okta_idp_observed` on `google_idp_name`,
  and cross-source conflict on `dmarc_policy`). These scalars originate in
  OIDC / UserRealm / DMARC collection, never in a raw apex record, so a pure-DNS
  adversary cannot set them. The runner asserts only the declared scalars are set,
  so a transition is attributable to the named injection.

## Record grammar

Owned and queried names use the reserved `.invalid` namespace. A record value that
must carry a vendor fingerprint to exercise the matcher (an Exchange Online MX, an
Akamai edge CNAME or NS) uses the vendor's documented infrastructure suffix with a
synthetic `synthetic-*` label; verification tokens use the `synthetic-domain-token`,
`synthetic-ms-token`, and `synthetic-token` sentinels. The corpus cannot contain a
real target value because the schema has nowhere to put one.

## Running

From the repository root:

```
python validation/adversarial_corpus/run.py            # score, print the report
python validation/adversarial_corpus/run.py --write     # refresh results.json
```

`fixtures.json` is the corpus. `results.json` is the aggregate-only output and
records the fixture-set SHA-256 the run bound to, so the result names exactly what
it ran against. The dated memo is
[`validation/2026-08-17-adversarial-corpus-round.md`](../2026-08-17-adversarial-corpus-round.md).

## Relationship to the binding-layer harness

`validation/adversarial_properties.py` plants evidence and measures threshold
crossings at the abstract binding layer through `infer()`; it stays as the
binding-layer property check. This corpus is its record-layer complement: the
binding-layer harness shows what the network would do with a signal, the
record-layer corpus shows whether an adversary can produce that signal from records.
The gap between them is the gate's coverage.
