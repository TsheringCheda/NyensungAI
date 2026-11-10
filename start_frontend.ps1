$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot 'frontend')
if (-not (Test-Path 'node_modules')) {
    npm ci
}
npm run dev
