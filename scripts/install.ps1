# One-line installer / updater for recon (Windows PowerShell).
#
# Install or update (same command - re-run any time to upgrade to the latest):
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.ps1 | iex"
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

function Install-OrUpgrade-Uv {
    Write-Host "==> Installing/updating $Package with uv ..." -ForegroundColor Green
    # `upgrade` succeeds only if already installed; on first run it fails and we
    # fall through to install. Either path lands on the latest published version.
    uv tool upgrade $Package 2>$null
    if ($LASTEXITCODE -ne 0) { uv tool install $Package }
}

function Install-OrUpgrade-Pipx {
    Write-Host "==> Installing/updating $Package with pipx ..." -ForegroundColor Green
    pipx upgrade $Package 2>$null
    if ($LASTEXITCODE -ne 0) { pipx install $Package }
}

Write-Host "==> recon installer (CLI: $Cli)" -ForegroundColor Cyan
Write-Host ""

if (Test-Have "uv") {
    Install-OrUpgrade-Uv
}
elseif (Test-Have "pipx") {
    Install-OrUpgrade-Pipx
}
else {
    Write-Host "Error: need uv or pipx. Install uv (recommended):" -ForegroundColor Red
    Write-Host '  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
    Write-Host "then re-run this installer."
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
