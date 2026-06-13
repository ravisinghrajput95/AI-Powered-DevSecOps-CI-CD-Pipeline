# CloudCart — local dev quick start (Windows PowerShell)
# Usage: .\scripts\start-local.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "=== CloudCart Local Setup ===" -ForegroundColor Cyan

# 1. Postgres via Docker
Write-Host "`n[1/3] Starting PostgreSQL..." -ForegroundColor Yellow
Set-Location $Root
docker compose up -d postgres
Start-Sleep -Seconds 8

# 2. Backend
Write-Host "`n[2/3] Backend — open a NEW terminal and run:" -ForegroundColor Yellow
Write-Host "  cd $Root\backend" -ForegroundColor White
Write-Host "  .\run-backend.ps1" -ForegroundColor White

# 3. Frontend
Write-Host "`n[3/3] Frontend — open another terminal and run:" -ForegroundColor Yellow
Write-Host "  cd $Root\frontend" -ForegroundColor White
Write-Host "  npm install" -ForegroundColor White
Write-Host "  npm run dev" -ForegroundColor White

Write-Host "`n=== URLs ===" -ForegroundColor Cyan
Write-Host "  App:      http://localhost:3000"
Write-Host "  API:      http://localhost:5000"
Write-Host "  Login:    admin / admin123"
Write-Host ""
