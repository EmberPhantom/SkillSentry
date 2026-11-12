# Install SkillSentry's command, skill-sentry-cli, on Windows from a published release.
#
#   powershell -ExecutionPolicy Bypass -File install.ps1               install, then run setup
#   powershell -ExecutionPolicy Bypass -File install.ps1 -NoSetup      install only
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Version 2.1.0rc1
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Wheel C:\path\skill_sentry_cli.whl
#   powershell -ExecutionPolicy Bypass -File install.ps1 -DryRun       show the steps; change nothing
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall    remove the command; data is kept
#
# No administrator rights are needed.  Everything goes under %LOCALAPPDATA%\skill-sentry-cli
# and the user PATH.  The download is checked against SHA256SUMS before anything is installed.
# Python 3.11 to 3.13 is required.  The sandbox itself needs Docker Desktop (see the user guide).
[CmdletBinding()]
param(
    [switch]$NoSetup,
    [switch]$Uninstall,
    [switch]$DryRun,
    [string]$Version = "2.1.1",
    [string]$Wheel = ""
)

$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 defaults to older TLS; GitHub requires TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "EmberPhantom/SkillSentry"
$AppHome = Join-Path $env:LOCALAPPDATA "skill-sentry-cli"
$VenvDir = Join-Path $AppHome "venv"
$VenvScripts = Join-Path $VenvDir "Scripts"
$DataDir = Join-Path $env:USERPROFILE ".skillsentry"

function Fail([string]$Message) {
    Write-Host "error: $Message" -ForegroundColor Red
    exit 1
}

if ($Version -notmatch '^[0-9A-Za-z.+-]+$') {
    Fail "not a version: $Version"
}

$WheelName = "skill_sentry_cli-$Version-py3-none-any.whl"
$BaseUrl = $env:SKILL_SENTRY_RELEASE_URL
if (-not $BaseUrl) {
    $BaseUrl = "https://github.com/$Repo/releases/download/v$Version"
}

function Get-UserPath {
    return [Environment]::GetEnvironmentVariable("Path", "User")
}

function Add-ToUserPath([string]$Folder) {
    $current = Get-UserPath
    $entries = @()
    if ($current) { $entries = $current -split ";" | Where-Object { $_ -ne "" } }
    if ($entries -contains $Folder) { return $false }
    $updated = (@($entries) + $Folder) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $updated, "User")
    return $true
}

function Remove-FromUserPath([string]$Folder) {
    $current = Get-UserPath
    if (-not $current) { return }
    $entries = $current -split ";" | Where-Object { $_ -ne "" -and $_ -ne $Folder }
    [Environment]::SetEnvironmentVariable("Path", ($entries -join ";"), "User")
}

function Find-Python {
    # The Python launcher first: `py -3.12` finds the version even when `python` is another one.
    $candidates = @(
        @("py", "-3.13"), @("py", "-3.12"), @("py", "-3.11"),
        @("python"), @("python3")
    )
    foreach ($candidate in $candidates) {
        $exe = $candidate[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $callArgs = @()
        if ($candidate.Count -gt 1) { $callArgs += $candidate[1..($candidate.Count - 1)] }
        $probe = "import sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] <= (3, 13) else 1)"
        & $exe @callArgs -c $probe *> $null
        if ($LASTEXITCODE -eq 0) { return ,(@($exe) + $callArgs) }
    }
    return $null
}

function Show-PythonHelp {
    Write-Host "Python 3.11 to 3.13 is required on Windows." -ForegroundColor Yellow
    Write-Host "Install Python 3.12 from https://www.python.org/downloads/ (tick 'Add python.exe to PATH')."
    Write-Host "Or run: winget install Python.Python.3.12"
    Write-Host "Then open a new PowerShell window and run this script again."
}

function Uninstall-SkillSentry {
    if (Get-Command pipx -ErrorAction SilentlyContinue) {
        $listed = pipx list --short 2>$null
        if ($listed -match '^skill-sentry-cli ') { pipx uninstall skill-sentry-cli }
    }
    if (Test-Path $VenvDir) { Remove-Item -Recurse -Force $VenvDir }
    if (Test-Path $AppHome) { Remove-Item -Recurse -Force $AppHome -ErrorAction SilentlyContinue }
    Remove-FromUserPath $VenvScripts
    Write-Host "Removed the skill-sentry-cli command."
    Write-Host "Kept your data: $DataDir (scan history, reports) and any skillsentry.toml you wrote."
    Write-Host "Delete that folder yourself if you no longer need it."
}

function Get-VerifiedWheel([string]$Target) {
    $sums = Join-Path $Target "SHA256SUMS"
    $file = Join-Path $Target $WheelName
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$WheelName" -OutFile $file
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS" -OutFile $sums

    $line = Get-Content $sums | Where-Object { $_ -match "\s\*?$([regex]::Escape($WheelName))$" } | Select-Object -First 1
    if (-not $line) { Fail "$WheelName is not listed in SHA256SUMS" }
    $expected = ($line -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Fail "checksum mismatch for $WheelName; the download is not trusted"
    }
    Write-Host "Checksum verified."
    return $file
}

if ($Uninstall) {
    Uninstall-SkillSentry
    exit 0
}

if ($DryRun) {
    Write-Host "Dry run. Nothing will be downloaded or installed."
    Write-Host "  version:  $Version"
    if ($Wheel) {
        if (-not (Test-Path $Wheel)) { Fail "no such wheel: $Wheel" }
        Write-Host "  wheel:    $Wheel (local, checksum not verified)"
    } else {
        Write-Host "  download: $BaseUrl/$WheelName"
        Write-Host "  checksum: $BaseUrl/SHA256SUMS"
    }
    if (Get-Command pipx -ErrorAction SilentlyContinue) {
        Write-Host "  install:  pipx install --force <wheel>"
    } else {
        Write-Host "  install:  private venv at $VenvDir"
        Write-Host "  PATH:     add $VenvScripts to your user PATH"
    }
    exit 0
}

$python = Find-Python
if (-not $python) {
    Show-PythonHelp
    exit 1
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("skill-sentry-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    if ($Wheel) {
        if (-not (Test-Path $Wheel)) { Fail "no such wheel: $Wheel" }
        $wheelPath = Join-Path $tmp $WheelName
        Copy-Item $Wheel $wheelPath
        Write-Host "Using local wheel (checksum not verified)."
    } else {
        $wheelPath = Get-VerifiedWheel $tmp
    }

    if (Get-Command pipx -ErrorAction SilentlyContinue) {
        # Pin pipx to the Python we validated; otherwise it may pick a newer, unsupported one.
        $pythonExe = (& $python[0] @($python | Select-Object -Skip 1) -c "import sys; print(sys.executable)").Trim()
        pipx install --force --python $pythonExe $wheelPath
        if ($LASTEXITCODE -ne 0) { Fail "pipx could not install the package" }
    } else {
        New-Item -ItemType Directory -Path $AppHome -Force | Out-Null
        $exe = $python[0]
        $pyArgs = @()
        if ($python.Count -gt 1) { $pyArgs += @($python | Select-Object -Skip 1) }
        & $exe @pyArgs -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { Fail "could not create the virtual environment in $VenvDir" }
        & (Join-Path $VenvScripts "python.exe") -m pip install --quiet --upgrade --force-reinstall $wheelPath
        if ($LASTEXITCODE -ne 0) { Fail "pip could not install the package" }
        if (Add-ToUserPath $VenvScripts) {
            Write-Host "Added $VenvScripts to your user PATH. Open a new PowerShell window to use it."
        }
    }
    Write-Host "Installed skill-sentry-cli $Version."
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if (-not $NoSetup) {
    $command = Get-Command skill-sentry-cli -ErrorAction SilentlyContinue
    if ($command) {
        & skill-sentry-cli setup
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Setup did not finish. Fix the lines above, then run: skill-sentry-cli setup"
        }
    } else {
        Write-Host "Open a new PowerShell window, then run: skill-sentry-cli setup"
    }
}
