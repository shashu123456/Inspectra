# One-shot TestPyPI release for Inspectra.
# Usage: double-click PUBLISH-TESTPYPI.bat, or:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\publish-testpypi.ps1
# Options: -SkipGates (skip pytest/ruff/mypy), -SkipInstallCheck (skip clean-venv install test)

[CmdletBinding()]
param(
    [switch]$SkipGates,
    [switch]$SkipInstallCheck,
    [switch]$DryRun
)

# Native tools (git, pip, pytest, twine) write warnings to stderr; with "Stop"
# PowerShell 5.1 turns those into terminating errors. We check $LASTEXITCODE
# explicitly after every native call instead.
$ErrorActionPreference = "Continue"

function Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    OK  $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "    FAIL $msg" -ForegroundColor Red; exit 1 }

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
Write-Host "Inspectra -> TestPyPI" -ForegroundColor White
Write-Host "repo: $repo"

# ---------------------------------------------------------------- 0. python
Step "Locating Python"
$py = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $cmd) { Fail "No .venv and no 'python' on PATH. Create the venv first." }
    $py = $cmd.Source
}
& $py --version
Ok "python: $py"

# ---------------------------------------------------------------- 1. token
Step "Reading TestPyPI token"
$tokenFile = Join-Path $repo ".secrets\testpypi_token.txt"
if (-not (Test-Path $tokenFile)) {
    New-Item -ItemType Directory -Force (Split-Path $tokenFile) | Out-Null
    Set-Content -Path $tokenFile -Value "# Paste the TestPyPI token (starts with pypi-) on the next line`nPASTE_TESTPYPI_TOKEN_HERE"
    Fail "Token file was missing. I created it at:`n      $tokenFile`n    Paste your token there, save, and run this again."
}
$token = (Get-Content $tokenFile -Raw) -split "`r?`n" |
    Where-Object { $_.Trim() -ne "" -and -not $_.TrimStart().StartsWith("#") } |
    Select-Object -First 1
if ($token) { $token = $token.Trim() }
if (-not $token -or $token -notmatch '^pypi-') {
    Fail "No valid token in $tokenFile`n    It must be a single line starting with 'pypi-'.`n    Get one at https://test.pypi.org/manage/account/token/"
}
Ok "token loaded ($($token.Substring(0,12))..., $($token.Length) chars)"

# ---------------------------------------------------------------- 2. secrets ignored
Step "Verifying the token file cannot be committed"
Push-Location $repo
$relToken = ".secrets/testpypi_token.txt"
$tracked = (& git ls-files -- $relToken 2>$null)
& git check-ignore -q -- $relToken 2>$null
$ignoreExit = $LASTEXITCODE
Pop-Location
if ($tracked) { Fail "$relToken is TRACKED by git. Run: git rm --cached $relToken" }
if ($ignoreExit -ne 0) { Fail ".secrets/ is not in .gitignore. Add it before publishing." }
Ok ".secrets/ is gitignored and untracked"

# ---------------------------------------------------------------- 3. packaging metadata
Step "Checking packaging metadata"
$pjPath = Join-Path $repo "pyproject.toml"
$pj = Get-Content $pjPath -Raw
$changed = @()

if ($pj -match '(?m)^name\s*=\s*"inspectra"\s*$') {
    $pj = $pj -replace '(?m)^name\s*=\s*"inspectra"\s*$', 'name = "inspectra-cli"'
    $changed += 'name: inspectra -> inspectra-cli'
}
if ($pj -notmatch '(?m)^name\s*=\s*"inspectra-cli"\s*$') {
    Fail "Could not set distribution name. Current line:`n    $((Select-String -Path $pjPath -Pattern '^name\s*=').Line)"
}
if ($pj -match '(?m)^version\s*=\s*"1\.0\.0"\s*$') {
    $pj = $pj -replace '(?m)^version\s*=\s*"1\.0\.0"\s*$', 'version = "2.0.0"'
    $changed += 'version: 1.0.0 -> 2.0.0'
}
$version = (Select-String -Path $pjPath -Pattern '^version\s*=\s*"([^"]+)"').Matches.Groups[1].Value
if (-not $version) { $version = (Select-String -InputObject $pj -Pattern '^version\s*=\s*"([^"]+)"').Matches.Groups[1].Value }
if (-not $version) { Fail "No static version in pyproject.toml. Add version = `"2.0.0`" under [project]." }

if ($pj -notmatch '(?m)^inspectra-cli\s*=\s*"inspectra\.cli:main"\s*$') {
    $pj = $pj -replace '(?m)^(inspectra\s*=\s*"inspectra\.cli:main"\s*)$', "`$1`ninspectra-cli = `"inspectra.cli:main`""
    if ($pj -match '(?m)^inspectra-cli\s*=') { $changed += 'added console script: inspectra-cli' }
}

if ($changed.Count -gt 0) {
    Copy-Item $pjPath "$pjPath.bak" -Force
    Set-Content -NoNewline -Path $pjPath -Value $pj
    $changed | ForEach-Object { Ok $_ }
    Ok "backup: pyproject.toml.bak"
} else {
    Ok "metadata already correct"
}

$initPath = Join-Path $repo "src\inspectra\__init__.py"
if (Test-Path $initPath) {
    $init = Get-Content $initPath -Raw
    if ($init -match '__version__\s*=\s*"[^"]+"' -and $init -notmatch "__version__\s*=\s*`"$([regex]::Escape($version))`"") {
        $init = $init -replace '__version__\s*=\s*"[^"]+"', "__version__ = `"$version`""
        Set-Content -NoNewline -Path $initPath -Value $init
        Ok "src/inspectra/__init__.py __version__ -> $version"
    }
}
Write-Host "    releasing: inspectra-cli $version" -ForegroundColor White

# ---------------------------------------------------------------- 4. gates
if (-not $SkipGates) {
    Step "Running gates (tests, lint, types)"
    & $py -m pytest -q --no-cov
    if ($LASTEXITCODE -ne 0) { Fail "pytest failed - nothing was uploaded" }
    & $py -m ruff check .
    if ($LASTEXITCODE -ne 0) { Fail "ruff check failed - nothing was uploaded" }
    & $py -m ruff format --check .
    if ($LASTEXITCODE -ne 0) { Fail "ruff format --check failed - nothing was uploaded" }
    & $py -m mypy
    if ($LASTEXITCODE -ne 0) { Fail "mypy failed - nothing was uploaded" }
    Ok "all gates green"
} else {
    Write-Host "    (gates skipped)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 5. build
Step "Building sdist + wheel"
& $py -m pip install --quiet --upgrade build twine
if ($LASTEXITCODE -ne 0) { Fail "could not install build/twine" }
if (Test-Path (Join-Path $repo "dist")) { Remove-Item -Recurse -Force (Join-Path $repo "dist") }
& $py -m build
if ($LASTEXITCODE -ne 0) { Fail "python -m build failed" }
& $py -m twine check (Get-ChildItem (Join-Path $repo "dist") -File | ForEach-Object { $_.FullName })
if ($LASTEXITCODE -ne 0) { Fail "twine check failed" }
Ok "artifacts: $((Get-ChildItem (Join-Path $repo 'dist') -File | ForEach-Object { $_.Name }) -join ', ')"

# ---------------------------------------------------------------- 6. wheel payload
Step "Verifying the wheel ships data files and templates"
$whl = Get-ChildItem (Join-Path $repo "dist") -Filter *.whl | Select-Object -First 1
$check = @"
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
need = ['data/header_rules.json', 'data/fingerprints.json', 'data/directory_wordlist.txt', 'report/templates/report.html.j2']
missing = [n for n in need if not any(k.endswith(n) for k in names)]
print('    files in wheel:', len(names))
for n in need:
    print(('    OK   ' if n not in missing else '    MISS ') + n)
sys.exit(1 if missing else 0)
"@
$check | & $py - $whl.FullName
if ($LASTEXITCODE -ne 0) {
    Fail "The wheel is missing package data. Add this to pyproject.toml, rebuild, and re-run:`n`n[tool.hatch.build.targets.wheel.force-include]`n`"src/inspectra/data`" = `"inspectra/data`"`n`"src/inspectra/report/templates`" = `"inspectra/report/templates`""
}
Ok "wheel payload complete"

if ($DryRun) {
    Step "Dry run - stopping before upload"
    Get-ChildItem (Join-Path $repo "dist") -File | ForEach-Object { Write-Host "    would upload: $($_.Name) ($([math]::Round($_.Length/1KB,1)) KB)" }
    Write-Host "    remove -DryRun to publish inspectra-cli $version to TestPyPI" -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------- 7. upload
Step "Uploading to TestPyPI"
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = $token
try {
    & $py -m twine upload --non-interactive --repository testpypi (Get-ChildItem (Join-Path $repo "dist") -File | ForEach-Object { $_.FullName })
    if ($LASTEXITCODE -ne 0) { Fail "upload failed (see the message above)" }
} finally {
    Remove-Item Env:TWINE_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:TWINE_USERNAME -ErrorAction SilentlyContinue
}
Ok "uploaded"

# ---------------------------------------------------------------- 8. clean-venv proof
if (-not $SkipInstallCheck) {
    Step "Installing from TestPyPI into a clean venv (waits for index propagation)"
    $tmp = Join-Path $env:TEMP ("ipk-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    & $py -m venv $tmp
    & "$tmp\Scripts\python.exe" -m pip install --quiet --upgrade pip
    $installed = $false
    for ($i = 1; $i -le 6; $i++) {
        & "$tmp\Scripts\pip.exe" install --quiet -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ "inspectra-cli==$version"
        if ($LASTEXITCODE -eq 0) { $installed = $true; break }
        Write-Host "    attempt $i failed, retrying in 20s..." -ForegroundColor Yellow
        Start-Sleep -Seconds 20
    }
    if (-not $installed) { Fail "could not install inspectra-cli==$version from TestPyPI" }
    & "$tmp\Scripts\inspectra.exe" --version
    & "$tmp\Scripts\inspectra-cli.exe" --version
    Remove-Item -Recurse -Force $tmp
    Ok "clean install works"
}

# ---------------------------------------------------------------- 9. summary
Step "Done"
Write-Host "    project : https://test.pypi.org/project/inspectra-cli/$version/" -ForegroundColor White
Write-Host "    install : pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ inspectra-cli==$version" -ForegroundColor White
Write-Host ""
Write-Host "Next: commit the metadata change (pyproject.toml, __init__.py, .gitignore)." -ForegroundColor Yellow
if (Test-Path "$pjPath.bak") { Write-Host "A backup of the old pyproject is at pyproject.toml.bak - delete it before committing." -ForegroundColor Yellow }
