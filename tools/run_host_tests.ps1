# TrustGate host test runner for Windows (PowerShell)
# Runs deterministic unit tests (41 checks), boundary checks, and soak tests.
param(
    [switch]$Soak,
    [int]$SoakMillis = 3000000
)

$ErrorActionPreference = "Stop"

# Locate GCC
$cmd = Get-Command gcc.exe -ErrorAction SilentlyContinue
$gcc = if ($cmd) { $cmd.Source } else { $null }
if (-not $gcc) {
    if (Test-Path "C:\msys64\ucrt64\bin\gcc.exe") {
        $gcc = "C:\msys64\ucrt64\bin\gcc.exe"
    } else {
        Write-Error "GCC compiler not found. Please install GCC or add it to PATH."
        exit 1
    }
}

Write-Host "=== 1. Checking Source Boundary ===" -ForegroundColor Cyan
$badIncludes = Get-ChildItem src\*.c, src\*.h | Select-String '#include.*(secure_internal|secure_hw|provisioned_cards|secure_passage)' | Where-Object { $_.Path -notlike "*ns_attack.c" }
if ($badIncludes) {
    Write-Host "Boundary violation detected in:" -ForegroundColor Red
    $badIncludes | ForEach-Object { Write-Host "  $($_.Path):$($_.LineNumber): $($_.Line)" -ForegroundColor Red }
    exit 1
} else {
    Write-Host "Boundary check OK: Non-secure sources only reference public secure_api.h" -ForegroundColor Green
}

Write-Host "`n=== 2. Running Deterministic Unit Tests (41 Checks) ===" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path build | Out-Null
& $gcc -std=gnu11 -Wall -Wextra -DTG_HOST_TEST -Iinclude -o build/host_tests.exe test/test_main.c test/hw_stub.c secure/secure_core.c secure/secure_passage.c
if ($LASTEXITCODE -ne 0) {
    Write-Error "Unit test compilation failed."
    exit $LASTEXITCODE
}

& ./build/host_tests.exe
if ($LASTEXITCODE -ne 0) {
    Write-Error "Unit tests failed!"
    exit $LASTEXITCODE
}

if ($Soak) {
    Write-Host "`n=== 3. Running Random Soak Test (48M Simulated ms across 8 seeds) ===" -ForegroundColor Cyan
    & $gcc -std=gnu11 -O2 -DTG_HOST_TEST -Iinclude -o build/fuzz.exe test/fuzz.c test/hw_stub.c secure/secure_core.c secure/secure_passage.c
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Fuzz compilation failed."
        exit $LASTEXITCODE
    }

    $seeds = 1..8
    foreach ($s in $seeds) {
        Write-Host "Testing Seed $s (dense)..." -ForegroundColor Yellow
        & ./build/fuzz.exe $s $SoakMillis 0
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        Write-Host "Testing Seed $s (quiet)..." -ForegroundColor Yellow
        & ./build/fuzz.exe $s $SoakMillis 1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    Write-Host "All 48M ms soak tests passed with all invariants held!" -ForegroundColor Green
} else {
    Write-Host "`n(Tip: Run with -Soak to execute the 48M ms randomized invariant soak test across all 8 seeds)" -ForegroundColor DarkGray
}

Write-Host "`n=== All host tests passed! ===" -ForegroundColor Green
