# Start CloudCart API (local dev)
$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path ".\venv\Scripts\Activate.ps1")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
}

Write-Host "Activating venv and installing dependencies..."
& ".\venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q
pip uninstall -y jwt 2>$null  # wrong package; app needs PyJWT

$env:DATABASE_URL = "postgresql://cloudcart:CloudCartDB_Pass123!@localhost:5432/cloudcart"

Write-Host ""
Write-Host "Starting API at http://localhost:5000"
Write-Host "Health: http://localhost:5000/health"
Write-Host ""

python app.py
