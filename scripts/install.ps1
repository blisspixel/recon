# One-line installer / updater for recon (Windows PowerShell).
#
# Install or update (same command — re-run any time to upgrade to the latest):
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.ps1 | iex"
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Prefers uv (fast, manages its own Python); falls back to pipx; bootstraps pipx
# with system Python if neither is present. Idempotent: a second run upgrades.

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
    $python = "python"
    if (-not (Test-Have $python)) { $python = "py" }
    if (-not (Test-Have $python)) {
        Write-Host "Error: need uv, pipx, or Python 3.11+. Install uv (recommended):" -ForegroundColor Red
        Write-Host '  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
        Write-Host "then re-run this installer."
        exit 1
    }
    $ver = & $python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
    if (-not $ver -or ([version]$ver -lt [version]"3.11")) {
        Write-Host "Error: Python 3.11+ is required (found $ver), or install uv first:" -ForegroundColor Red
        Write-Host '  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
        exit 1
    }
    Write-Host "==> pipx/uv not found; bootstrapping pipx with Python ..." -ForegroundColor Yellow
    & $python -m pip install --user pipx --quiet
    & $python -m pipx ensurepath
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    Install-OrUpgrade-Pipx
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
Write-Host "Update later: re-run this same command."
Write-Host "Uninstall:    uv tool uninstall $Package   (or: pipx uninstall $Package)"
Write-Host ""
