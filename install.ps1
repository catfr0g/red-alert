$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (
    -not (Test-Path -Path "pyproject.toml") -or
    -not (Test-Path -Path "requirements.txt") -or
    -not (Test-Path -Path ".env.example")
) {
    Write-Error "install.ps1: run this script from the Red Alert repository root."
    exit 1
}

$PbsRelease = "20260901"
$PbsVersion = "3.14.7"
$LocalAppData = $env:LOCALAPPDATA
if ([string]::IsNullOrEmpty($LocalAppData)) {
    $LocalAppData = Join-Path $env:USERPROFILE "AppData\Local"
}
$PythonCache = Join-Path $LocalAppData "red-alert\python-$PbsVersion"
$StandalonePython = Join-Path $PythonCache "python\python.exe"

function Test-Python314 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$File,
        [string[]]$PrefixArgs = @()
    )
    & $File @PrefixArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 14) else 1)" 2>$null
    return $LASTEXITCODE -eq 0
}

function Get-PbsTarget {
    $Arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) {
        $Arch = $env:PROCESSOR_ARCHITEW6432
    }
    switch ($Arch) {
        "AMD64" { return "x86_64-pc-windows-msvc" }
        "ARM64" { return "aarch64-pc-windows-msvc" }
        default {
            Write-Error "install.ps1: unsupported architecture: $Arch"
            exit 1
        }
    }
}

function Install-StandalonePython {
    $Target = Get-PbsTarget
    $Name = "cpython-${PbsVersion}+${PbsRelease}-${Target}-install_only_stripped.tar.gz"
    $Url = "https://github.com/astral-sh/python-build-standalone/releases/download/${PbsRelease}/${Name}"
    $Archive = Join-Path $env:TEMP $Name
    Write-Host "install.ps1: downloading Python $PbsVersion..."
    Invoke-WebRequest -Uri $Url -OutFile $Archive
    New-Item -ItemType Directory -Force -Path $PythonCache | Out-Null
    $Extracted = Join-Path $PythonCache "python"
    if (Test-Path -Path $Extracted) {
        Remove-Item -Recurse -Force -Path $Extracted
    }
    tar -xzf $Archive -C $PythonCache
    Remove-Item -Force -Path $Archive
    if (-not (Test-Path -Path $StandalonePython)) {
        Write-Error "install.ps1: standalone Python is missing after extract."
        exit 1
    }
    & $StandalonePython -m pip --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $StandalonePython -m ensurepip --default-pip
    }
}

$PythonFile = $null
$PythonPrefix = @()
if ((Get-Command py -ErrorAction SilentlyContinue) -and (Test-Python314 -File "py" -PrefixArgs @("-3.14"))) {
    $PythonFile = "py"
    $PythonPrefix = @("-3.14")
}
else {
    foreach ($Name in @("python3.14", "python3", "python")) {
        if ((Get-Command $Name -ErrorAction SilentlyContinue) -and (Test-Python314 -File $Name)) {
            $PythonFile = $Name
            break
        }
    }
}
if (-not $PythonFile -and (Test-Path -Path $StandalonePython) -and (Test-Python314 -File $StandalonePython)) {
    $PythonFile = $StandalonePython
}

if (-not $PythonFile) {
    Install-StandalonePython
    $PythonFile = $StandalonePython
    if (-not (Test-Python314 -File $PythonFile)) {
        Write-Error "install.ps1: failed to install Python 3.14+."
        exit 1
    }
}

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if ((Test-Path -Path ".venv") -and (-not (Test-Path -Path $VenvPython) -or -not (Test-Python314 -File $VenvPython))) {
    Remove-Item -Recurse -Force -Path ".venv"
}

if (-not (Test-Path -Path ".venv")) {
    & $PythonFile @PythonPrefix -m venv .venv
}

& $VenvPython -m pip install -r requirements.txt

if (-not (Test-Path -Path ".env")) {
    Copy-Item -Path ".env.example" -Destination ".env"
}

$BinDir = Join-Path $env:USERPROFILE ".local\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$Target = Join-Path $Root ".venv\Scripts\red-alert.exe"
$Shim = Join-Path $BinDir "red-alert.cmd"
Set-Content -Path $Shim -Value "@`"$Target`" %*" -Encoding ascii

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ([string]::IsNullOrEmpty($UserPath)) {
    $UserPath = ""
}
if ($UserPath -notlike "*$BinDir*") {
    if ($UserPath) {
        [Environment]::SetEnvironmentVariable("Path", "$BinDir;$UserPath", "User")
    }
    else {
        [Environment]::SetEnvironmentVariable("Path", $BinDir, "User")
    }
}
$env:PATH = "$BinDir;$env:PATH"

Write-Host "Red Alert is ready. Next: red-alert --help"
