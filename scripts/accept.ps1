# Re-run the library, optional TCP, and optional oracle checks on the
# current MoonBit toolchain. Exit non-zero on failure. This script does
# not run or rewrite bench/results.

$ErrorActionPreference = "Continue"

function Invoke-Checked {
  param(
    [scriptblock]$Command,
    [string]$Label
  )
  & $Command
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("FAIL  {0} (exit {1})" -f $Label, $LASTEXITCODE)
    exit $LASTEXITCODE
  }
}

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

function Section([string]$Name) {
  Write-Output ""
  Write-Output ("== {0} ==" -f $Name)
}

Section "toolchain"
$moonCmd = Get-Command moon -ErrorAction SilentlyContinue
$mooncCmd = Get-Command moonc -ErrorAction SilentlyContinue
if (-not $moonCmd) {
  Write-Host "FAIL  moon not on PATH"
  exit 1
}
if (-not $mooncCmd) {
  Write-Host "FAIL  moonc not on PATH"
  exit 1
}
Write-Output ("moon=" + $moonCmd.Source)
Write-Output ("moonc=" + $mooncCmd.Source)
if ($env:MOONC_OVERRIDE) {
  Write-Output ("MOONC_OVERRIDE=" + $env:MOONC_OVERRIDE)
}
Invoke-Checked { moon version --all } "moon version --all"

Section "library"
Invoke-Checked { moon update } "moon update"
Invoke-Checked { moon check --deny-warn --target native } "moon check native"
Invoke-Checked { moon test --target native } "moon test native"
Invoke-Checked { moon fmt --check } "moon fmt --check"
Invoke-Checked { moon info } "moon info"
Invoke-Checked { moon run --target native example } "example"
Invoke-Checked { moon run --target native example/pipe } "example/pipe"

$moonHome = if ($env:MOON_HOME -and $env:MOON_HOME.Trim() -ne "") {
  $env:MOON_HOME
} else {
  Join-Path $env:USERPROFILE ".moon"
}
$asyncDir = Join-Path $moonHome "lib\core\async"
Section "tcp"
if (Test-Path -LiteralPath $asyncDir) {
  Invoke-Checked { moon -C example/tcp update } "tcp update"
  Invoke-Checked { moon -C example/tcp check --deny-warn --target native } "tcp check"
  Invoke-Checked { moon -C example/tcp test --target native --package ppyj663/noise-tcp-example } "tcp test"
  Invoke-Checked { moon -C example/tcp run --target native . } "tcp run"
} else {
  Write-Output ("SKIP  {0} is not present (library-only toolchain)" -f $asyncDir)
}

Section "oracle"
$py = $null
if ($env:NOISE_ORACLE_PYTHON -and $env:NOISE_ORACLE_PYTHON.Trim() -ne "") {
  $py = $env:NOISE_ORACLE_PYTHON
} else {
  $c = Get-Command python3 -ErrorAction SilentlyContinue
  if (-not $c) {
    $c = Get-Command python -ErrorAction SilentlyContinue
  }
  if ($c) {
    $py = $c.Source
  }
}

if ($py) {
  & $py -c "import cryptography" 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) {
    Invoke-Checked { & $py scripts/fallback_oracle.py --check } "fallback oracle"
  } else {
    Write-Output "SKIP  Python cryptography is not available"
  }
} else {
  Write-Output "SKIP  Python is not available"
}

Section "done"
Write-Output "acceptance passed"
exit 0
