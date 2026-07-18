# Installer / updater for recon (Windows PowerShell).
#
# Review this file from a release-tag checkout, then install or update with:
#   powershell -ExecutionPolicy ByPass -File .\scripts\install.ps1
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Prefers uv (fast, manages its own Python); falls back to pipx. Idempotent: a
# second run upgrades.

$ErrorActionPreference = "Stop"

$Package = "recon-tool"
$Cli = "recon"

function Test-Have($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

# Run a native command without letting it abort the script. Windows PowerShell
# 5.1 turns a native command's stderr into a terminating NativeCommandError when
# $ErrorActionPreference is "Stop" (even with 2>$null), and uv/pipx write normal
# progress to stderr, so we relax the preference locally and branch on the real
# exit code instead.
function Invoke-Tool {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Cmd)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # Render each line as plain text. Under Windows PowerShell 5.1 a native
        # command's stderr arrives as ErrorRecord objects; [string] yields just
        # the message, so progress lines print clean instead of decorated with
        # CategoryInfo / FullyQualifiedErrorId noise.
        & $Cmd[0] @($Cmd[1..($Cmd.Count - 1)]) 2>&1 | ForEach-Object { Write-Host ([string]$_) }
    }
    finally {
        $ErrorActionPreference = $prev
    }
    return $LASTEXITCODE
}

function Test-PackageInstalled($ListCmd) {
    # The list command (`uv tool list` / `pipx list`) prints the package name in
    # its stanza; match it anywhere in the combined stdout+stderr.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $listed = & $ListCmd[0] @($ListCmd[1..($ListCmd.Count - 1)]) 2>&1 | Out-String
    }
    finally {
        $ErrorActionPreference = $prev
    }
    return ($listed -match "\b$([regex]::Escape($Package))\b")
}

function Install-OrUpgrade-Uv {
    if (Test-PackageInstalled @("uv", "tool", "list")) {
        Write-Host "==> Upgrading $Package with uv ..." -ForegroundColor Green
        if ((Invoke-Tool uv tool upgrade $Package) -ne 0) { throw "uv tool upgrade $Package failed" }
    }
    else {
        Write-Host "==> Installing $Package with uv ..." -ForegroundColor Green
        if ((Invoke-Tool uv tool install $Package) -ne 0) { throw "uv tool install $Package failed" }
    }
}

function Install-OrUpgrade-Pipx {
    if (Test-PackageInstalled @("pipx", "list")) {
        Write-Host "==> Upgrading $Package with pipx ..." -ForegroundColor Green
        if ((Invoke-Tool pipx upgrade $Package) -ne 0) { throw "pipx upgrade $Package failed" }
    }
    else {
        Write-Host "==> Installing $Package with pipx ..." -ForegroundColor Green
        if ((Invoke-Tool pipx install $Package) -ne 0) { throw "pipx install $Package failed" }
    }
}

function Write-MissingToolHelp {
    Write-Host "Error: install uv or pipx first, then re-run this installer." -ForegroundColor Red
    Write-Host "Recommended:"
    Write-Host "  https://docs.astral.sh/uv/getting-started/installation/"
    Write-Host "Alternative:"
    Write-Host "  https://pipx.pypa.io/stable/installation/"
    exit 1
}

Write-Host "==> recon installer (CLI: $Cli)" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Have "uv") -and -not (Test-Have "pipx")) {
    Write-MissingToolHelp
}

if (Test-Have "uv") {
    Install-OrUpgrade-Uv
}
elseif (Test-Have "pipx") {
    Install-OrUpgrade-Pipx
}
else {
    Write-MissingToolHelp
}

Write-Host ""
Write-Host "==> Done." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open a NEW terminal (so PATH updates take effect)"
Write-Host "  2. Offline install check: $Cli --version"
Write-Host "  3. Optional online source connectivity: $Cli doctor"
Write-Host ""
Write-Host "Quick start:"
Write-Host "  DNS infrastructure may observe lookup queries; the only default"
Write-Host "  target-owned HTTP request is the MTA-STS policy fetch. Google CSE"
Write-Host "  and BIMI direct probes run only with --direct-probes."
Write-Host "  $Cli example.com"
Write-Host "  $Cli example.com --json"
Write-Host ""
Write-Host "Optional: enable tab-completion with  $Cli --install-completion"
Write-Host ""
Write-Host "Update later: re-run this same command."
Write-Host "Uninstall:    uv tool uninstall $Package   (or: pipx uninstall $Package)"
Write-Host ""
