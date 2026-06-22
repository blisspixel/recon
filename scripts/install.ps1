# One-line installer / updater for recon (Windows PowerShell).
#
# Install or update (same command - re-run any time to upgrade to the latest):
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.ps1 | iex"
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Prefers uv (fast, manages its own Python); falls back to pipx; bootstraps uv
# automatically if neither is present. Idempotent: a second run upgrades.

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

# Pull any PATH changes a just-run installer made (uv writes to the *User* PATH
# and to ~\.local\bin) into this session so a freshly bootstrapped uv resolves
# without a new terminal.
function Sync-Path {
    $user = [Environment]::GetEnvironmentVariable("PATH", "User")
    $machine = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $localBin = Join-Path $env:USERPROFILE ".local\bin"
    $env:PATH = (@($localBin, $user, $machine, $env:PATH) | Where-Object { $_ }) -join ";"
}

function Install-Uv {
    Write-Host "==> Neither uv nor pipx found. Bootstrapping uv ..." -ForegroundColor Green
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        Invoke-Expression (Invoke-RestMethod "https://astral.sh/uv/install.ps1")
    }
    finally {
        $ErrorActionPreference = $prev
    }
    Sync-Path
}

Write-Host "==> recon installer (CLI: $Cli)" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Have "uv") -and -not (Test-Have "pipx")) {
    Install-Uv
}

if (Test-Have "uv") {
    Install-OrUpgrade-Uv
}
elseif (Test-Have "pipx") {
    Install-OrUpgrade-Pipx
}
else {
    Write-Host "Error: uv bootstrap did not put 'uv' on PATH. Install uv manually:" -ForegroundColor Red
    Write-Host '  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
    Write-Host "then open a NEW terminal and re-run this installer."
    exit 1
}

Write-Host ""
Write-Host "==> Done." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open a NEW terminal (so PATH updates take effect)"
Write-Host "  2. Run: $Cli doctor"
Write-Host ""
Write-Host "Quick start:"
Write-Host "  $Cli example.com"
Write-Host "  $Cli example.com --json"
Write-Host ""
Write-Host "Optional: enable tab-completion with  $Cli --install-completion"
Write-Host ""
Write-Host "Update later: re-run this same command."
Write-Host "Uninstall:    uv tool uninstall $Package   (or: pipx uninstall $Package)"
Write-Host ""
