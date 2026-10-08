# Maintenance review, 2026-10-08

This bounded review starts at commit `7be070155f2e31be4dd2ed68a026b469be31c9d4`.
It covers README and roadmap truth, the two open maintenance issues, and one
bug and security review round. This record captures local validation before
release preparation; the changelog records the v2.19.12 release batch.
The review made no target-domain collection or paid provider calls.

## Documentation review

The README's installation commands, compact output, cache caveats and local MCP
setup agree with source and the generated documentation gates. Preserve its
short onboarding structure and absolute links. Both roadmaps described shipped
v2.19 corrections as future batches; they now distinguish those completed
tranches from current maintenance and upstream-blocked work.

## Open issues and decisions

### Dependency refresh, issue 197

[Issue 197](https://github.com/blisspixel/recon/issues/197) tracks the failed
grouped proposal in [PR 195](https://github.com/blisspixel/recon/pull/195).
Re-resolve selected packages with uv 0.11.17 rather than copying that proposal's
lockfile. Current stable metadata was checked on 2026-10-08.

| Boundary | Reviewed change | Reason |
|---|---|---|
| Runtime | AnyIO 4.14.2 to 4.15.1 | Submodule access compatibility; existing async contracts stay under test |
| SDK transport | HTTPX2 and HTTPCore2 2.12.0 to 2.13.1 | Early stream cleanup fixes; preserve recon's separate pinned HTTPX/HTTPCore transport boundary |
| CLI | Typer 0.27.1 to 0.27.3 | Escape terminal control characters in error messages; raise the install floor |
| Runtime typing | typing-extensions 4.15.0 to 4.16.0 | TypedDict inheritance and protocol compatibility fixes |
| Build only | Hatchling 1.31.0 to 1.32.4 | Reject readme paths outside the project; preserve the repaired plugin interface |
| Development only | Hypothesis 6.168.5, Ruff 0.16.10, Pyright 1.1.414 | Compatible test and static-analysis maintenance |
| Mutation only | multidict 6.7.1 to 6.9.1 | Exclude CVE-2026-104874 in cosmic-ray's aiohttp dependency graph |
| Optional validation only | Anthropic 0.125.0, OpenAI 2.54.0 | Review the proposed compatible SDK increments without invoking provider APIs |

Hatchling adds `tomlkit` to the build closure and uses core metadata 2.5.
Update both exact roots, the complete hashed export, supply-chain documentation
and the explicit package-set invariant together. Do not add build or validation
SDK packages to the published runtime. New validation SDK major lines are
outside this compatible refresh and require separate harness migration work.

The production lock and blocking MCP rows retain 2.2.0. Upstream
[MCP SDK 2.3.0](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.3.0)
is now stable and is selected by the fresh installed-wheel resolver. Keep
that packaged-runtime observation separate from the three frozen CI rows;
roadmap labels now describe the locked baseline rather than upstream currency.

Primary sources:

- [AnyIO history](https://anyio.readthedocs.io/en/stable/versionhistory.html)
- [HTTPX2 2.13.0 changes](https://github.com/pydantic/httpx2/releases/tag/v2.13.0)
- [Typer 0.27.3 changes](https://github.com/fastapi/typer/releases/tag/0.27.3)
- [typing-extensions 4.16.0](https://github.com/python/typing_extensions/releases/tag/4.16.0)
- [Hatchling release history](https://github.com/pypa/hatch/releases)
- [Anthropic 0.125.0](https://github.com/anthropics/anthropic-sdk-python/releases/tag/v0.125.0)
- [OpenAI 2.54.0](https://github.com/openai/openai-python/releases/tag/v2.54.0)
- [multidict advisory](https://github.com/aio-libs/multidict/security/advisories/GHSA-54p9-h82j-f925)

### Upstream pip transport, issue 187

[Issue 187](https://github.com/blisspixel/recon/issues/187) remains blocked.
[PyPI](https://pypi.org/project/pip/) still lists pip 26.2.1 as the stable
release. Its vendored urllib3 is 2.7.0; installing urllib3 2.8.0 separately does
not replace that copy. The upstream
[proxy TLS](https://github.com/urllib3/urllib3/security/advisories/GHSA-8988-9cw3-xx77)
and [chunk-size](https://github.com/urllib3/urllib3/security/advisories/GHSA-vxq7-64xx-v4gw)
fixes therefore cannot be claimed for ordinary pip downloads.

Keep the complete frozen dependency audit's `--disable-pip` path, patched
standalone transport floor and no-resolver regression tests. Do not vendor a
fork or select a preview release. Recheck the bundled implementation when a
stable pip fix appears. This blocker does not establish exploitation of recon,
and urllib3 remains outside recon's domain-collection runtime.

## Bug and security corrections

- SPF: require one selected SPF record before policy credit or redirect
  traversal at every hop, following [RFC 7208 section 4.5](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5).
  Preserve declaration references, include counts, unrelated TXT and raw data.
  Apply the same selection to replay and expire incompatible old result caches.
  Preserve record multiplicity when different wire chunking yields equal text.
- TXT: use real concatenated RDATA bytes rather than zone-file presentation
  escapes. Decode UTF-8 with replacement for malformed byte sequences; retain
  control-byte sanitization at human rendering boundaries.
- Ephemeral rules: a connected local MCP client could retain arbitrarily long
  TXT owner strings despite count quotas. Bound complete retained patterns and
  relative owner labels before admission, preserving underscore and nested owners.
- Client config: a prepared local FIFO could block install or doctor before
  byte limits applied. Share the descriptor-validated, nonblocking regular-file
  reader while preserving config symlinks, BOM, whitespace-empty files and mtime
  behavior. Cache and artifact readers retain their stricter symlink policy.

Both security findings are low severity and require a local client or filesystem
preparer. Static review found no confirmed SSRF or private-destination bypass.
This is bounded source review, not exhaustive repository coverage or deployment
certification. Synthetic regressions establish behavior, not real-world accuracy.

## Acceptance

Require lint, strict Pyright, the full 90.2 percent branch-coverage gate,
frozen lock and export parity, complete dependency audit, all three exact MCP
SDK probes, installed-wheel checks, and matching hashes from two independent
builds under a fixed epoch. Record local results separately from hosted CI.
Issue 197 also requires the hosted OS/Python matrix and exact merged-main
acceptance through the normal workflow. The local evidence below predates that
publication sequence and does not establish its outcome.

Local evidence was collected on Windows with Python 3.14.7 and uv 0.11.17:

- The complete test suites passed 7,885 parallel tests and 40 serial MCP doctor
  tests, with 29 platform or optional skips and at least 91.80 percent coverage with
  branch measurement enabled. Actual POSIX FIFO tests are skipped on Windows;
  descriptor rejection and cleanup have portable coverage.
- Ruff and strict Pyright pass. The final full-gate log is retained locally at
  `.agent/maintenance-final-gate.log`.
- The frozen lock check, build export parity and full all-group, all-extra
  dependency audit pass; the audit reports no known vulnerabilities.
- All 24 checks pass for each exact MCP SDK row: 1.28.1, 2.0.0 and 2.2.0.
  A separate exploratory 2.3.0 row also passes all 24 checks.
- Two independent Python 3.11 builds under the baseline commit's fixed
  `SOURCE_DATE_EPOCH` produce matching sdist and wheel hashes with the hashed
  build constraints. The installed-wheel probe uses a fresh runtime resolver,
  launches both manifests and makes zero external socket attempts.

These are local implementation and packaging results. They do not replace
the hosted OS/Python, mutation, CodeQL or release acceptance jobs for this patch.
