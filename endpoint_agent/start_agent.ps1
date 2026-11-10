$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host 'Created endpoint_agent/.env. Set NYENSUNG_AGENT_API_KEY to match backend/.env.' -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path 'venv\Scripts\Activate.ps1')) {
    python -m venv venv
}
. .\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python agent.py
