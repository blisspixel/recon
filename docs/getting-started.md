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
recon contoso.com
```

Use fictional or reserved domains in examples and docs. Public validation work
with real apexes stays in gitignored local workspaces.

## Input Normalization

Pass a public-suffix domain (for example `contoso.com`). A bare hostname without
a dot is rejected with `Invalid domain format` rather than treated as an unknown
CLI command.

recon accepts common paste shapes:

```bash
recon https://www.contoso.com/path
recon contoso.com.
recon mail.contoso.com
```

By default, recon reduces a URL or sub-host to the registrable apex where tenant,
MX, SPF, DMARC, and CT evidence usually live. Pass `--exact` only when you want
DNS facts for the literal host:

```bash
recon mail.contoso.com --exact
```

## Output Modes

```bash
recon contoso.com
recon contoso.com --full
recon contoso.com --explain
recon contoso.com --plain
recon contoso.com --json
recon contoso.com --md
```

Services are already present in the compact default panel. `--verbose` keeps
that summary and adds certificate and evidence detail plus per-source status on
stderr. `--full` adds the verbose detail, all known domains, and posture
observations. `--services` remains accepted for compatibility; new
workflows do not need it.

Use `--explain` when a claim matters. It shows the evidence chain behind the
result. Some insight and posture associations are reconstructed, so graph
reachability is not exact generation-time lineage.

Use `--plain` for screen readers, grep, and other linear-text workflows. It
removes color and layout while preserving the observation content.
This is the linear view for a standard single-domain lookup. Chain, compare,
exposure, and gaps reports use their own formats; batch and delta have
mode-specific output.

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
request, and the usual public CT and identity-source boundaries apply.

At terminal widths below 70 columns, command help automatically switches to a
complete linear layout so long option names remain visible.

If a lookup times out or every online source fails, run `recon doctor` to
check source connectivity, then retry the lookup.

## Batch and Delta

```bash
recon batch domains.txt --json
recon batch domains.txt --ndjson
cat domains.txt | recon batch - --json
recon delta contoso.com
```

Batch files contain one domain per line. Blank lines and lines beginning with
`#` are ignored. Valid URL, sub-host, and apex spellings that normalize to the
same registrable apex are resolved once, with the first occurrence preserved.
Malformed values deduplicate only when their trimmed, lowercased spellings
match, so distinct malformed inputs retain separate diagnostics. The reader
accepts at most 10,000 non-comment records before deduplication, 1 KiB of UTF-8
per logical line, and 10 MiB of UTF-8 in total. The full behavior is documented
in [operational-contract.md](operational-contract.md).

## MCP Setup

```bash
recon mcp install --client=claude-desktop
recon mcp install --client=cursor --dry-run
recon mcp doctor
```

Use [mcp.md](mcp.md) for client-specific config, tool lists, approval guidance,
and troubleshooting.

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

## Next Reads

- [how-it-works.md](how-it-works.md)
- [limitations.md](limitations.md)
- [schema.md](schema.md)
- [automation-examples.md](automation-examples.md)
- [mcp.md](mcp.md)
