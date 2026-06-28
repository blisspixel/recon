# Getting Started

This guide covers install, update, uninstall, and the first commands to run.
The short product overview is in [README.md](../README.md).

## Requirements

- Python 3.11 or newer.
- Windows, macOS, or Linux.
- No API keys, credentials, paid accounts, or external services owned by recon.

## Install or Update

Install with `uv` or `pipx`:

```bash
uv tool install recon-tool
# or
pipx install recon-tool
```

The platform installer prefers `uv`, falls back to `pipx`, and asks you to
install one of those tools if neither is present. It does not execute a remote
tool installer on your behalf. Running the same command later updates recon.

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.ps1 | iex"
```

**macOS or Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.sh | bash
```

Open a new terminal after install, then run:

```bash
recon doctor
```

## Update

```bash
recon update
recon update --check
```

`recon update` detects whether the package was installed with `uv`, `pipx`,
`pip`, or Homebrew and runs the matching upgrade command.

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
recon doctor
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
recon doctor
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

## First Lookup

```bash
recon contoso.com
```

Use fictional or reserved domains in examples and docs. Public validation work
with real apexes stays in gitignored local workspaces.

## Input Normalization

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
recon contoso.com --json
recon contoso.com --md
```

Use `--explain` when a claim matters. It shows the evidence chain behind the
result.

## Batch and Delta

```bash
recon batch domains.txt --json
recon batch domains.txt --ndjson
cat domains.txt | recon batch - --json
recon delta contoso.com
```

Batch files contain one domain per line. The batch input cap is documented in
[operational-contract.md](operational-contract.md).

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
PATH and restart the terminal.

## Next Reads

- [how-it-works.md](how-it-works.md)
- [limitations.md](limitations.md)
- [schema.md](schema.md)
- [automation-examples.md](automation-examples.md)
- [mcp.md](mcp.md)
