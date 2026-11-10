$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot 'backend')
if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host 'Created backend/.env. Set SECRET_KEY and AGENT_API_KEY before continuing.' -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path 'venv\Scripts\Activate.ps1')) {
    python -m venv venv
}
. .\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
