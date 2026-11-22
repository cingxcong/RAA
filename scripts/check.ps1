<#
.SYNOPSIS
    Run formatting, lint, type and test checks.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Virtual environment not found. Run .\scripts\bootstrap.ps1 first."
}

$env:TMP = Join-Path $root ".tmp"
$env:TEMP = $env:TMP
New-Item -ItemType Directory -Force -Path $env:TMP | Out-Null

Push-Location $root
try {
    Write-Host "ruff format --check"
    & $python -m ruff format --check src tests

    Write-Host "ruff check"
    & $python -m ruff check src tests

    Write-Host "mypy"
    & $python -m mypy src

    Write-Host "pytest"
    & $python -m pytest
}
finally {
    Pop-Location
}
