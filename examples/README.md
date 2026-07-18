# Examples

Sample files showing recon's input and output formats.

- `sample-output.json`  -  Example JSON output from
  `recon gamma.invalid --json --no-fusion`. All data is fictional. The
  explicit flag explains why fusion arrays are present but empty.
- `sample-batch.txt`  -  Example batch input file for `recon batch sample-batch.txt --json`.

Parser recipes for single lookup, batch array, NDJSON, delta, and cohort-summary
JSON modes live in [`docs/automation-examples.md`](../docs/automation-examples.md).

All depicted target labels, target domains, tenant IDs, and organization
identifiers are synthetic. Target domains use `.invalid`, which is reserved by
[RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html) for names that are
guaranteed to be invalid. Real provider infrastructure hostnames can appear
where needed to demonstrate documented DNS signatures or public endpoint
behavior; those are detection definitions, not evaluated targets.
