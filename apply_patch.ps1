$ErrorActionPreference = "Stop"
$PatchRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $PatchRoot

$PortalSource = Join-Path $PatchRoot "connections\portal_connection.py"
$VersionSource = Join-Path $PatchRoot "core\version_normalizer.py"
$PortalDest = Join-Path $ProjectRoot "connections\portal_connection.py"
$VersionDest = Join-Path $ProjectRoot "core\version_normalizer.py"

if (!(Test-Path $PortalDest) -or !(Test-Path $VersionDest)) {
    throw "Folder patch harus berada langsung di dalam root project Hardening Utility v2."
}

$Backup = Join-Path $ProjectRoot ("backup_portal_version_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -ItemType Directory -Force $Backup | Out-Null
Copy-Item $PortalDest (Join-Path $Backup "portal_connection.py")
Copy-Item $VersionDest (Join-Path $Backup "version_normalizer.py")
Copy-Item -Force $PortalSource $PortalDest
Copy-Item -Force $VersionSource $VersionDest

$Python = Get-Command python -ErrorAction SilentlyContinue
if ($Python) {
    & python -m py_compile $PortalDest $VersionDest
    if ($LASTEXITCODE -ne 0) { throw "Syntax check gagal. File lama tersedia di $Backup" }
}

Write-Host "Patch versi Portal berhasil diterapkan." -ForegroundColor Green
Write-Host "Backup file lama: $Backup"
Write-Host "Jalankan kembali: python app.py"
