# Getting Started

This guide covers install, update, uninstall, and the first commands to run.
The short product overview is in [README.md](../README.md).

## Requirements

- Python 3.11 through 3.14. The latest Python 3.14 patch is recommended; every
  version in that tested range retains the same supported behavior and output
  contracts. Later Python versions are not yet part of the compatibility claim.
- Windows, macOS, or Linux.
- The recon runtime needs no API keys, credentials, paid accounts, or external
  services owned by recon. Optional GitHub Release verification uses an
  authenticated GitHub CLI session or `GH_TOKEN` with public read access.

## Install or Update

Install with `uv` or `pipx`:

```bash
uv tool install recon-tool
# or
pipx install recon-tool
```

The optional platform helpers ask you to install `uv` or `pipx` if neither is
present. A helper from a release-tag checkout installs exactly that release,
preserves the sole manager that already owns `recon-tool`, and refuses dual or
unmanaged ownership with recovery guidance. It does not execute a remote tool
installer on your behalf. Review the local file before running it. To update,
review and run the helper from the newer release tag.

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -File .\scripts\install.ps1
```

**macOS or Linux:**

```bash
bash scripts/install.sh
```

These commands assume a reviewed local checkout. Do not pipe mutable branch
content directly into a shell.

Open a new terminal after install, then run an offline verification of the
installed command:

```bash
recon --version
```

To test online connectivity to recon's public data sources, run:

```bash
recon doctor
```

## Verify a Published Release

Security-sensitive consumers can verify the exact GitHub Release asset set,
completed SBOM, tag-bound bundle, PyPI attestations, cross-channel SHA-256
parity, and both wheel entry points before optionally installing the verified
local wheel. Releases produced by the current workflow include the SBOM in the
signed subject set; the exact v2.6.3 historical exception covers its wheel and
sdist while still requiring SBOM structure validation. The complete
macOS/Linux and Windows PowerShell paths are in the
[consumer verification quick path](supply-chain.md#consumer-verification-quick-path).

## Update

```bash
recon update
recon update --check
```

`recon update` detects whether the package was installed with `uv`, `pipx`,
`pip`, or an editable checkout and runs the matching upgrade command when it can.
`recon update --check` reports separately when the installed version matches
PyPI, is behind PyPI, or is newer than the latest published release. It never
offers to replace a newer local or source build with an older PyPI release.

`recon doctor` reports the running version, Python executable, package location,
and detected installation method. It also warns when the first `recon` launcher
on PATH reports a different version, which commonly means a stale global install
is taking precedence over the intended environment.

Direct package-manager commands also work:

```bash
uv tool upgrade recon-tool
pipx upgrade recon-tool
pip install -U recon-tool
```

## Uninstall

Use the tool that installed recon:

```bash
uv tool uninstall recon-tool
pipx uninstall recon-tool
pip uninstall recon-tool
```

## Install with pipx

`pipx` is a good default for command-line tools because it creates an isolated
environment and puts the script on PATH.

```bash
pipx install recon-tool
recon --version
```

## Install in a Virtual Environment

```bash
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

or:

```bash
source .venv/bin/activate
```

Then install and verify:

```bash
pip install -U recon-tool
recon --version
```

## Install from a Git Checkout

```bash
git clone https://github.com/blisspixel/recon.git
cd recon
pip install -e .
```

For development work in this repository, prefer:

```bash
uv sync
uv run python scripts/check.py
```

After an editable or environment install, either the `recon` console script or
the package module entry works:

```bash
recon --version
python -m recon_tool --version
```

## First Lookup

Lookups make DNS queries which recursive and authoritative DNS infrastructure
may observe. The only default request to a target-owned HTTP endpoint is the
standards-defined MTA-STS policy fetch at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. Google CSE and BIMI direct
probes run only when `--direct-probes` is explicitly enabled.

```bash
recon example.com
```

recon ships no offline demo mode: this is a real lookup command, but an ordinary
lookup may reuse a recent result from the default 24-hour cache. Pass
`--no-cache` for fresh collection. Reserved names such as `example.com` return a
real panel of stray public residue from unrelated test configurations,
including a meaningless display name, at High confidence. It shows you the
shape of the output, not a result about any organization. Point recon at a
domain you want to review to see a real footprint.

Use explicit synthetic identities under reserved namespaces in examples and
docs. Public validation work with real apexes stays in gitignored local
workspaces.

The panel's two dot rows answer different questions, so they can disagree
without either being wrong. `Confidence` is a deterministic merged tier over
source count, same-claim corroboration, and source degradation; a degraded
source lowers it. It is not a raw source count and not a probability.
`Model support` is threshold-relative: where a claim's hand-set uncertainty band
sits against the model's decision threshold. A single-source record can carry a
full model display, and the panel says so on the row when the two sit two steps
apart. Definitions: [glossary.md](glossary.md); detail:
[how-it-works.md](how-it-works.md).

`--confidence-mode strict` (or `--strict`) drops hedging qualifiers like
`observed` and `indicators` from insight lines, but only on a dense-evidence
record: High confidence with at least three sources. A thin-evidence record
keeps its hedges under `strict` by design, because dropping the hedge on sparse
evidence would overclaim. So the same insight can read one way on a dense record
and another on a thin one, and identically when neither is dense.

## Input Normalization

Pass a public-suffix domain (for example `example.com`). A bare hostname without
a dot is rejected with `Invalid domain format` rather than treated as an unknown
CLI command.

recon accepts common paste shapes:

```bash
recon https://www.example.com/path
recon example.com.
recon mail.example.com
```

By default, recon reduces a URL or sub-host to the registrable apex where tenant,
MX, SPF, DMARC, and CT evidence usually live. Pass `--exact` only when you want
DNS facts for the literal host:

```bash
recon mail.example.com --exact
```

## Output Modes

```bash
recon example.com
recon example.com --full
recon example.com --explain
recon example.com --plain
recon example.com --json
recon example.com --md
```

Services are already present in the compact default panel, grouped by lane
(Email, Identity, Cloud, Security, AI, Data & Analytics, Collaboration,
Business Apps). `--md` uses those same lanes. The default `--md` report is still
a briefing: it caps insights and related domains and omits unattributed
matches. `--json` and `--md --full` are the downstream connection map: every
lane including empty ones, every vendor row with its evidence role, catalog
summaries, and related hosts classified by first label (`auth.`, `shop.`,
`workday.`). `--verbose` keeps the panel summary and adds certificate and
evidence detail plus per-source status on stderr. `--full` adds the verbose
detail, all known domains, and posture observations. `--services` remains
accepted for compatibility; new workflows do not need it.

Use `--explain` when a claim matters. It shows the evidence chain behind the
result. Built-in generated insights retain their exact emitting rule and
evidence-or-observation-scope association. Signal-adjacent, conflict, lexical,
confidence, and legacy posture associations can still be reconstructed. Flat
explanations label that distinction. In explained JSON,
`exact_provenance_complete` and `lineage_disconnected_terminals` answer the
exact-lineage question; schema-version-1 `provenance_complete` retains its
broader graph-reachability meaning.

Use `--plain` for screen readers, grep, and other linear-text workflows. It
renders the default panel's rows as indented `key: value` lines with no color
or box-drawing: the same claims the panel shows, in the same order, under the
stable schema names, and with the same cuts. Grep for `provider:` and
`tenant_id:`, not `Provider`.

A record whose mail vendor and identity vendor differ leads with `mail:` and
`identity:` (the role split from
[ADR-0015](adr/0015-role-split-vendor-claims-in-the-default-view.md)) and still
emits `provider:` after them, carrying its usual MX-delivery-path summary, so
one grep works on every record. On a split it prints that role, `provider:
Google Workspace (MX delivery path)`, because the vendor word is one `mail:`
just said and the role is the reason it came back. Long lists are cut the way
the panel cuts them: `related_domains:` carries the high-signal selection and
`related_domains_note:` states how many more exist, and `insights:` is capped
with an `insights_note:` beside it. Each note names `--plain --full` and counts
against it, so what you heard plus what the note states is what that command
prints. The panel's own footer points at the panel's `--full`, which stays
curated, so the same record can carry two different remainders: each is exact
about the output it names.

Add `--full` for the complete structured record, including Bayesian internals
such as `posterior_observations` and `interval_low`:

```bash
recon example.com --plain          # the panel, linearised
recon example.com --plain --full   # every field the record carries
```

Before 2.15, plain `--plain` always emitted the full record. If you parse it
for a field outside the panel, add `--full`;
[ADR-0016](adr/0016-plain-emits-the-panel-record.md) records the change, and
`--json` remains the surface recommended for automation. Either mode tracks the
panel's default/detailed split ([ADR-0012](adr/0012-default-view-evidence-role-visibility.md)),
so evidence-role qualifiers are compacted unless you add `--explain`.
This is the linear view for a standard single-domain lookup. Chain, compare,
exposure, and gaps reports use their own formats; batch and delta have
mode-specific output.

## Exit Codes

Every command follows one exit-code contract, so a script can branch on the
outcome without parsing output. The same table is in
[schema.md](schema.md) for machine consumers.

| Code | Meaning |
|---|---|
| 0 | Success: the command completed and produced output |
| 1 | General handled error, for example a missing optional dependency or a failed `doctor` check |
| 2 | Validation: bad input rejected before any work, for example a malformed domain or mutually exclusive flags |
| 3 | No data: the target resolved but nothing was available to report |
| 4 | Internal: a caught network or pipeline failure, or the last-resort crash handler |

## Inspect Local Cache State

`cache show` reads metadata only. The default overview enumerates cache
filenames for exact totals but opens at most the lexicographically first 100
result files and 100 CT files. Use `--all` only when a complete inspection is
worth the additional local work:

```bash
recon cache show
recon cache show --all
```

recon resolves its config, cache, and state directories in one order:
`RECON_CONFIG_DIR` if set, else an existing legacy `~/.recon/`, else the XDG base
directories (`$XDG_CONFIG_HOME/recon`, `$XDG_CACHE_HOME/recon`,
`$XDG_STATE_HOME/recon`). On Windows with none of those set, that resolves to
`%USERPROFILE%\.config\recon`, `%USERPROFILE%\.cache\recon`, and
`%USERPROFILE%\.local\state\recon`. `recon doctor` prints the resolved paths.

An interrupted atomic write can leave a cache-writer-shaped temporary file.
The overview counts that residue without reading or printing its payload,
exits 4, and points to the confirmed `recon cache clear --all` workflow. That
clear-all operation removes both completed entries and recognized temporary
write artifacts, while unrelated `*.tmp` files are left alone.

## Explore the Local Catalogs

The list, search, and show commands below are local and do not query a domain or
another network source:

```bash
recon fingerprints list
recon fingerprints search email
recon fingerprints show <slug>
recon signals list
recon signals search email
recon signals show "<signal name>"
```

Fingerprint slugs are named public-record indicators. A slug may have more than
one catalog record, so `fingerprints show` renders every matching record and
its detection rules, relationship hints, tiers, and verification dates. Signals
are derived reportable-observation definitions built from candidate fingerprint
slugs and metadata conditions. Human fingerprint search is a ten-slug preview;
add `--json` to retrieve every matching catalog record. Category filters use
word-prefix matching for one token and literal phrase matching for multiword
queries in both the CLI and MCP server. Human catalog detail output strips
terminal controls from locally extended text and visibly marks values truncated
after 1,024 characters.

`recon fingerprints test` is different: it resolves every domain in the chosen
local corpus through the ordinary live lookup pipeline. DNS infrastructure may
observe those queries, MTA-STS remains the one default target-owned HTTP
request, and the usual public CT and identity-source boundaries apply. The
entire UTF-8 input is validated before the first lookup: at most 1 MiB total,
1 KiB per logical line, and 500 non-comment domain rows. Valid URL and sub-host
forms normalize to their apex and duplicate normalized domains resolve once.
Any malformed row rejects the file before collection begins. Human output
counts matches, clean non-matches, and lookup errors separately. JSON rows
retain `matched` and `detail` and add `status` with `matched`, `not_matched`, or
`error`, so failed collection is not negative evidence.
Valid corpus invocations retain exit 0 even when one or every lookup reports an
error. Automation must inspect each JSON row's `status` instead of treating the
process exit status as collection success.

At terminal widths below 70 columns, command help automatically switches to a
complete linear layout so long option names remain visible. Ranked signal
search results keep relevance order and carry an explicit category and
confidence instead of implying category grouping.

If a lookup times out or every online source fails, run `recon doctor` to
check source connectivity, then retry the lookup.

## Namespace Review Bundles

NamespaceReviewBundle v1 is the separate, caller-owned contract for a
deterministic evidence handoff about one namespace. It composes exactly one
fresh baseline that bypasses the lookup-result cache with evidence-linked
review candidates and one role-neutral human rendering. Direct probes are fixed
off; CT is the only optional collection lane. CT may use its documented cache,
and the artifact records that outcome separately. Temporal facts do not become
a universal fresh or stale verdict.

```bash
recon review example.com
recon review example.com --json
recon review example.com --output example-review.json
recon review example.com --no-ct
```

The default view is deterministic Markdown. `--json` emits the validated v1
artifact, while `--output` writes that JSON artifact locally and refuses to
replace an existing file unless `--force` is supplied. Through MCP, call
`build_review_bundle(domain, no_ct=false, timeout_seconds=120)` for the same
structured artifact. The `domain_report` prompt uses that tool once and asks the
client to render the standing section order without adding other analysis
tools. Full contract, failure, privacy, and rendering semantics are in
[review-bundles.md](review-bundles.md).

## Batch and Delta

```bash
recon batch domains.txt --json
recon batch domains.txt --json --include-ecosystem --summary --summary-schema 2.2
recon batch domains.txt --ndjson
cat domains.txt | recon batch - --json
recon delta example.com
```

The longer batch command emits one portfolio evidence bundle for the exact
operator-supplied set. It preserves ordered success and error records, adds
observable ecosystem hyperedges, and attaches the aggregate-only cohort summary
under `cohort_summary`. Shared infrastructure and configuration are public
observations, not proof of ownership, control, a corporate relationship, or
relative security. Plain batch JSON and the streaming NDJSON path keep their
existing shapes.

Batch files contain one domain per line. Blank lines and lines beginning with
`#` are ignored. Valid URL, sub-host, and apex spellings that normalize to the
same registrable apex are resolved once, with the first occurrence preserved.
Malformed values deduplicate only when their trimmed, lowercased spellings
match, so distinct malformed inputs retain separate diagnostics. The reader
accepts at most 10,000 non-comment records before deduplication, 1 KiB of UTF-8
per logical line, and 10 MiB of UTF-8 in total. The full behavior is documented
in [operational-contract.md](operational-contract.md).

## Observation Capsules

Capture one caller-owned artifact, replay it without network access, or compare
two artifacts while keeping observation, collection, time, and interpretation
changes separate:

```bash
recon capsule capture example.com --output example-before.json
recon capsule replay example-before.json
recon capsule compare example-before.json example-after.json --json
```

Capture uses the ordinary public collection boundary. Capsule files may retain
public verification tokens, tenant identifiers, and related domains, so protect
them and review them before sharing. recon does not upload, schedule, or retain
them. Full semantics and the separate JSON Schema are in
[observation-capsules.md](observation-capsules.md).

## MCP Setup

```bash
recon mcp install --client=claude-desktop
recon doctor --mcp
recon mcp doctor
recon doctor --client=claude-desktop
```

Run the checks in that order. They validate the static server registry, the
live local stdio tools and JSON resources, and the saved configuration for the
same client. The live doctor does not inspect client configuration. Use
[mcp.md](mcp.md) for client-specific config, tool lists, approval guidance, and
troubleshooting.

## Shell Completion

```bash
recon --install-completion
recon --show-completion
```

Restart the shell after installing completion.

## Windows PATH Notes

If `recon` is not found after `pip install`, the script likely went into your
user Scripts directory, which may not be on PATH. Prefer the installer, `uv`, or
`pipx`. If you must use bare `pip`, add the matching user Scripts directory to
PATH and restart the terminal. As a temporary fallback while PATH is fixed:

```bash
python -m recon_tool --version
```

If that version differs from `recon --version`, run `recon doctor` from the
intended environment. Its `PATH recon launcher` row identifies the launcher
taking precedence so you can activate the intended environment or reinstall
that launcher with its package manager.

## Next Reads

- [how-it-works.md](how-it-works.md)
- [limitations.md](limitations.md)
- [schema.md](schema.md)
- [automation-examples.md](automation-examples.md)
- [mcp.md](mcp.md)
