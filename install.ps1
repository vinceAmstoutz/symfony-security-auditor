#Requires -Version 5.1
<#
.SYNOPSIS
    Installer for the symfony-security-auditor standalone binary on Windows.

.DESCRIPTION
    Downloads the Windows binary from the GitHub release, verifies its SHA-256
    checksum, and installs it.

.EXAMPLE
    irm https://raw.githubusercontent.com/vinceAmstoutz/symfony-security-auditor/main/install.ps1 | iex

.NOTES
    Environment variables:
      SSA_VERSION      release tag to install (default: latest)
      SSA_INSTALL_DIR  target directory (default: %LOCALAPPDATA%\Programs\symfony-security-auditor)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo = 'vinceAmstoutz/symfony-security-auditor'
$BinaryName = 'symfony-security-auditor'
$Version = if ($env:SSA_VERSION) { $env:SSA_VERSION } else { 'latest' }

function Resolve-Asset {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq 'ARM64') {
        Write-Warning 'No native ARM64 build — installing the x86_64 binary (runs under emulation).'
    }
    return "$BinaryName-windows-x86_64.exe"
}

function Get-Asset([string]$Url, [string]$OutFile) {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

function Test-Checksum([string]$File, [string]$ChecksumFile) {
    $expected = ((Get-Content -Raw $ChecksumFile).Trim() -split '\s+')[0]
    $actual = (Get-FileHash -Path $File -Algorithm SHA256).Hash
    if ($expected -ne $actual) {
        throw "checksum mismatch (expected $expected, got $actual)"
    }
}

function Resolve-InstallDir {
    if ($env:SSA_INSTALL_DIR) { return $env:SSA_INSTALL_DIR }
    return Join-Path $env:LOCALAPPDATA "Programs\$BinaryName"
}

function Install-Binary {
    $asset = Resolve-Asset
    $base = if ($Version -eq 'latest') {
        "https://github.com/$Repo/releases/latest/download"
    }
    else {
        "https://github.com/$Repo/releases/download/$Version"
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "Downloading $asset ($Version)…"
        try {
            Get-Asset "$base/$asset" "$tmp\$asset"
        }
        catch [System.Net.WebException] {
            $status = [int]$_.Exception.Response.StatusCode
            if ($status -eq 404) {
                throw @"
No Windows binary is published for release '$Version'.

Some older releases ship without a native Windows binary. Options:
  - Install a release that has one:  https://github.com/$Repo/releases
  - Composer:  composer require --dev $Repo   (as a Symfony bundle, needs PHP 8.3+)
  - WSL:       run the Linux installer inside WSL
"@
            }
            throw
        }
        Get-Asset "$base/$asset.sha256" "$tmp\$asset.sha256"
        Test-Checksum "$tmp\$asset" "$tmp\$asset.sha256"

        $installDir = Resolve-InstallDir
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        $target = Join-Path $installDir "$BinaryName.exe"
        Move-Item -Path "$tmp\$asset" -Destination $target -Force

        Write-Host "Installed $BinaryName to $target"
        $paths = ($env:Path -split ';')
        if ($paths -notcontains $installDir) {
            Write-Host "note: $installDir is not on your PATH — add it to run '$BinaryName' directly"
        }
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Install-Binary
