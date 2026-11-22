<#
.SYNOPSIS
    Create an isolated RAA development environment inside the repository.

.DESCRIPTION
    All caches and temporary files are redirected into the repository so the
    bootstrap does not write outside the project tree.
#>
[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$env:TMP = Join-Path $root ".tmp"
$env:TEMP = $env:TMP
$env:PIP_CACHE_DIR = Join-Path $root ".pip-cache"
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"

New-Item -ItemType Directory -Force -Path $env:TMP | Out-Null
New-Item -ItemType Directory -Force -Path $env:PIP_CACHE_DIR | Out-Null

$venv = Join-Path $root ".venv"
$pythonExe = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $pythonExe)) {
    Write-Host "Creating virtual environment at $venv"
    & $Python -m venv $venv
}

Write-Host "Upgrading pip"
& $pythonExe -m pip install --no-cache-dir --upgrade pip

Write-Host "Installing RAA in editable mode with development extras"
& $pythonExe -m pip install --no-cache-dir -e "${root}[dev]"

Write-Host ""
Write-Host "RAA is installed."
Write-Host "Activate with:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "Then run:"
Write-Host "  raa doctor"
