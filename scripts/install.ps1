# Installer / updater for recon (Windows PowerShell).
#
# Review this file from a release-tag checkout, then install or update with:
#   powershell -ExecutionPolicy ByPass -File .\scripts\install.ps1
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Preserves the manager that already owns recon. For a clean install, prefers
# uv (fast, manages its own Python) and falls back to pipx. The reviewed helper
# installs the exact release version represented by this source tag.

$ErrorActionPreference = "Stop"

$Package = "recon-tool"
$Version = "2.6.3"
$Spec = "$Package==$Version"
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
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($exitCode -ne 0) {
        Write-Host "Error: could not inspect $($ListCmd[0]) ownership for $Package." -ForegroundColor Red
        Write-Host $listed
        exit 1
    }
    return ($listed -match "\b$([regex]::Escape($Package))\b")
}

function Install-Exact-Uv {
    Write-Host "==> Installing reviewed $Spec with uv ..." -ForegroundColor Green
    if ((Invoke-Tool uv tool install --force $Spec) -ne 0) {
        Write-Host "Error: uv could not install $Spec." -ForegroundColor Red
        exit 1
    }
}

function Install-Exact-Pipx {
    Write-Host "==> Installing reviewed $Spec with pipx ..." -ForegroundColor Green
    if ((Invoke-Tool pipx install --force $Spec) -ne 0) {
        Write-Host "Error: pipx could not install $Spec." -ForegroundColor Red
        exit 1
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

$uvAvailable = Test-Have "uv"
$pipxAvailable = Test-Have "pipx"
if (-not $uvAvailable -and -not $pipxAvailable) {
    Write-MissingToolHelp
}

$uvOwns = $uvAvailable -and (Test-PackageInstalled @("uv", "tool", "list"))
$pipxOwns = $pipxAvailable -and (Test-PackageInstalled @("pipx", "list"))

if ($uvOwns -and $pipxOwns) {
    Write-Host "Error: both uv and pipx report an installed $Package." -ForegroundColor Red
    Write-Host "Uninstall one copy, confirm which 'recon' resolves on PATH, then re-run this helper."
    exit 1
}
if (-not $uvOwns -and -not $pipxOwns -and (Test-Have $Cli)) {
    Write-Host "Error: an existing '$Cli' command is not owned by uv or pipx." -ForegroundColor Red
    Write-Host "Use 'recon update', or uninstall that copy before running this helper."
    exit 1
}

if ($uvOwns) {
    $Manager = "uv"
    Install-Exact-Uv
}
elseif ($pipxOwns) {
    $Manager = "pipx"
    Install-Exact-Pipx
}
elseif ($uvAvailable) {
    $Manager = "uv"
    Install-Exact-Uv
}
elseif ($pipxAvailable) {
    $Manager = "pipx"
    Install-Exact-Pipx
}
else {
    Write-MissingToolHelp
}

Write-Host ""
Write-Host "==> Done. $Spec installed with $Manager." -ForegroundColor Green
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
Write-Host "Update later: review and run the helper from the newer release tag."
Write-Host "Uninstall:    uv tool uninstall $Package   (or: pipx uninstall $Package)"
Write-Host ""
