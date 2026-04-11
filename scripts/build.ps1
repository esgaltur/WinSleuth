$ErrorActionPreference = 'Stop'

Write-Host "Building WinSleuth (Release mode)..." -ForegroundColor Cyan
cargo build --release

$targetExe = "target\release\winsleuth.exe"
$distDir = "dist"

if (-not (Test-Path $targetExe)) {
    Write-Error "Build failed or executable not found at $targetExe"
    exit 1
}

if (-not (Test-Path $distDir)) {
    Write-Host "Creating dist directory..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

Write-Host "Copying executable to dist folder..." -ForegroundColor Cyan
Copy-Item -Path $targetExe -Destination "$distDir\winsleuth.exe" -Force

Write-Host "Build and packaging complete! Executable is located at: $distDir\winsleuth.exe" -ForegroundColor Green
