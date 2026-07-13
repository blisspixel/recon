# Examples

Sample files showing recon's input and output formats.

- `sample-output.json`  -  Example JSON output from
  `recon northwindtraders.com --json --no-fusion`. All data is fictional. The
  explicit flag explains why fusion arrays are present but empty.
- `sample-batch.txt`  -  Example batch input file for `recon batch sample-batch.txt --json`.

Parser recipes for single lookup, batch array, NDJSON, delta, and cohort-summary
JSON modes live in [`docs/automation-examples.md`](../docs/automation-examples.md).

All depicted target companies, target domains, tenant IDs, and organization
identifiers in these examples are fictional. Real provider infrastructure
hostnames can appear where they are needed to demonstrate documented DNS
signatures or public endpoint behavior. Target names use
[Microsoft's standard fictional company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges)
(Contoso, Fabrikam, Northwind Traders, and others), which are explicitly
intended for documentation and examples.
