# agent-broker installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/micsh/agent-broker/main/install.ps1 | iex
#   or:  .\install.ps1 [-InstallDir C:\tools\agent-broker]

param(
    [string]$InstallDir = "$env:USERPROFILE\.agent-broker\bin"
)

$ErrorActionPreference = "Stop"
$repo = "micsh/agent-broker"

Write-Host "🔌 Installing agent-broker..." -ForegroundColor Cyan

$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
Write-Host "   Release: $($release.tag_name)"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

foreach ($bin in @("agent-broker", "broker-mcp")) {
    $asset = "$bin-windows-x64.exe"
    $url = ($release.assets | Where-Object { $_.name -eq $asset }).browser_download_url

    if (-not $url) {
        Write-Host "   ⚠️  $asset not found in release, skipping" -ForegroundColor Yellow
        continue
    }

    $dest = Join-Path $InstallDir "$bin.exe"
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    Write-Host "   ✅ $bin → $dest" -ForegroundColor Green
}

Write-Host ""
Write-Host "✅ Installed to $InstallDir" -ForegroundColor Green
Write-Host ""
Write-Host "   Start the broker:  $InstallDir\agent-broker.exe" -ForegroundColor Yellow
Write-Host "   MCP server:        $InstallDir\broker-mcp.exe" -ForegroundColor Yellow
