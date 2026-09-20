# Installer / updater for recon (Windows PowerShell).
#
# Install from a local checkout with:
#   powershell -ExecutionPolicy ByPass -File .\scripts\install.ps1
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Preserves the manager that already owns recon. For a clean install, prefers
# uv and falls back to pipx. Bootstraps a pinned uv if neither is installed.
# Installs the exact recon release below, with no administrator privileges.

$ErrorActionPreference = "Stop"

$Package = "recon-tool"
$Version = "2.19.4"
$Spec = "$Package==$Version"
$Cli = "recon"
$UvVersion = "0.11.17"

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
    Write-Host "==> Installing $Spec with uv ..." -ForegroundColor Green
    if ((Invoke-Tool uv tool install --force $Spec --python 3.14) -ne 0) {
        Write-Host "Error: uv could not install $Spec." -ForegroundColor Red
        exit 1
    }
}

function Install-Exact-Pipx {
    Write-Host "==> Installing $Spec with pipx ..." -ForegroundColor Green
    if ((Invoke-Tool pipx install --force $Spec) -ne 0) {
        Write-Host "Error: pipx could not install $Spec." -ForegroundColor Red
        exit 1
    }
}

function Install-Uv {
    $uvBin = if ($env:UV_INSTALL_DIR) { $env:UV_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }
    $installer = Join-Path ([IO.Path]::GetTempPath()) ("recon-uv-" + [guid]::NewGuid() + ".ps1")
    $previousInstallDir = $env:UV_INSTALL_DIR
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    Write-Host "==> Installing uv $UvVersion ..." -ForegroundColor Green
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        # Download completely before executing in a child process. This also
        # isolates the upstream script's preferences and exit statements.
        Invoke-WebRequest -UseBasicParsing "https://astral.sh/uv/$UvVersion/install.ps1" -OutFile $installer
        $env:UV_INSTALL_DIR = $uvBin
        if ((Invoke-Tool powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer) -ne 0) {
            throw "uv installation failed. Check the output above and retry."
        }
    }
    finally {
        $env:UV_INSTALL_DIR = $previousInstallDir
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
    }
    $env:PATH = "$env:PATH;$uvBin"
    if (-not (Test-Have "uv")) {
        throw "uv installation did not create a launcher in $uvBin."
    }
}

function Set-CliPath {
    if ($Manager -eq "uv") {
        $binDir = & uv tool dir --bin
    }
    else {
        $binDir = & pipx environment --value PIPX_BIN_DIR
    }
    if ($LASTEXITCODE -ne 0 -or -not $binDir -or -not (Test-Path -LiteralPath $binDir -PathType Container)) {
        throw "$Manager did not report a valid executable directory."
    }
    if (($env:PATH -split ';') -notcontains $binDir) {
        $status = if ($Manager -eq "uv") { Invoke-Tool uv tool update-shell } else { Invoke-Tool pipx ensurepath }
        if ($status -ne 0) {
            throw "Could not add the $Manager executable directory to PATH."
        }
        # Append so an existing stale launcher still fails verification.
        $env:PATH = "$env:PATH;$binDir"
    }
}

function Get-CliCandidates {
    # Applications are the executable launchers PowerShell resolves through
    # PATH. Deduplicate and cap diagnostics so an accidental PATH cannot flood
    # installer output.
    return @(
        Get-Command $Cli -All -CommandType Application -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Source } |
            Where-Object { $_ } |
            Select-Object -Unique -First 20
    )
}

function Write-CliDiagnostics($Resolved, $Candidates) {
    if ($Resolved) {
        Write-Host "Resolved launcher: $Resolved"
    }
    else {
        Write-Host "Resolved launcher: (not found)"
    }
    Write-Host "Discovered candidates:"
    if ($Candidates.Count -gt 0) {
        foreach ($candidate in $Candidates) {
            $bounded = if ($candidate.Length -gt 1024) { $candidate.Substring(0, 1024) } else { $candidate }
            Write-Host "  $bounded"
        }
    }
    else {
        Write-Host "  (none)"
    }
}

function Test-InstalledCli {
    $candidates = @(Get-CliCandidates)
    $resolved = if ($candidates.Count -gt 0) { $candidates[0] } else { $null }
    $expected = "recon $Version"

    if (-not $resolved) {
        Write-Host "Error: $Spec was installed, but no '$Cli' launcher resolves on PATH." -ForegroundColor Red
        Write-CliDiagnostics $resolved $candidates
        return $false
    }

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $status = -1
    try {
        $outputLines = @(& $resolved --version 2>&1 | ForEach-Object { [string]$_ })
        $status = $LASTEXITCODE
    }
    catch {
        $outputLines = @([string]$_)
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    $output = $outputLines -join "`n"

    if ($status -ne 0) {
        Write-Host "Error: $Spec was installed, but '$resolved --version' exited $status." -ForegroundColor Red
        Write-CliDiagnostics $resolved $candidates
        return $false
    }
    if ($output -ceq $expected) {
        Write-Host "==> Verified $resolved reports $expected." -ForegroundColor Green
        return $true
    }

    $boundedOutput = if ($output.Length -gt 512) { $output.Substring(0, 512) } else { $output }
    if ($output -match '^recon\s+\S+$') {
        Write-Host "Error: $Spec was installed, but '$resolved --version' reported '$boundedOutput'; expected '$expected'." -ForegroundColor Red
    }
    else {
        Write-Host "Error: $Spec was installed, but '$resolved --version' returned malformed output '$boundedOutput'; expected '$expected'." -ForegroundColor Red
    }
    Write-CliDiagnostics $resolved $candidates
    return $false
}

Write-Host "==> recon installer (CLI: $Cli)" -ForegroundColor Cyan
Write-Host ""

$uvAvailable = Test-Have "uv"
$pipxAvailable = Test-Have "pipx"
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
    Install-Uv
    $Manager = "uv"
    Install-Exact-Uv
}

Set-CliPath
if (-not (Test-InstalledCli)) {
    exit 1
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
Write-Host "  $Cli `"<domain-you-want-to-review>`""
Write-Host "  $Cli `"<domain-you-want-to-review>`" --json"
Write-Host "  Syntax-only reserved example (live stray residue): $Cli example.com"
Write-Host ""
Write-Host "Optional: enable tab-completion with  $Cli --install-completion"
Write-Host ""
Write-Host "Update later: recon update"
Write-Host "Uninstall:    uv tool uninstall $Package   (or: pipx uninstall $Package)"
Write-Host ""
